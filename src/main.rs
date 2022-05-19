#![feature(label_break_value)]

extern crate cvesearch;
extern crate executor_future;
extern crate csv;
extern crate patch;
use clap::Clap;
use executor_future::{Promise, OperationalPromise, PollResult, ThreadPoolExecutor};

use std::sync::{Arc, Mutex};

use cvesearch::CVESearch;
use std::fs::File;
use std::io;
use std::io::{Read,Write};
use url::Url;
use walkdir::WalkDir;
use std::fs::DirBuilder;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use roctogen::api::repos;
use roctogen::auth::Auth;
use roctogen::endpoints::repos::{ReposGetCommitError, ReposGetCommitParams};

use csv::{WriterBuilder,StringRecord};
use patch::{Patch, ParseErrorOut, ParseError, Line};

#[derive(Clap)]
#[clap(version = "1.0", author = "llde")]
struct Opts {
    /// Path of the patchset
    #[clap(short = "i", long = "input")]
    input: String,
    /// Output of the files
    #[clap(short = "o", long = "output")]
    output: String,
    /// Number of threads the threadpool use
    #[clap(short = "t", long = "thread", default_value = "16")]
    threads: u32,
    /// Github Token for GithubAPI
    #[clap(short = "g", long = "token")]
    token : String,
}

#[derive(Clone)]
enum ErrorGithub{
    BadParents,
    NotFound,
    ParentNotFound,
    ExhaustedRequest,
    GenericError
}

#[derive(Clone)]
enum GithubResult{
 Ok((String, String, Vec<String>, String)),
 Err(ErrorGithub)
}

#[derive(Clone)]
struct FutureGithub{
    token : String,
    data : (String, String, String, String, Vec<String>),
    result : Arc<Mutex<Option<GithubResult>>>,
}
impl  FutureGithub{
    pub fn new(token : &str, data :  &(String, String, String, String, Vec<String>)) -> FutureGithub{
        FutureGithub{token : token.to_string(), data : data.clone(), result : Arc::new(Mutex::new(Option::None))}
    }
}


impl Promise for FutureGithub{
    type Output = GithubResult;
    fn run(&self){
        let opt: Option<ReposGetCommitParams> = None;
        let popt: Option<ReposGetCommitParams> = None;
        let auth = Auth::Token(self.token.clone());
        //     if i.2 == "linux"{continue;}
//        println!("{:?}", self.data);
        let commit_r = repos::new(&auth).get_commit(&self.data.1, &self.data.2, &self.data.3, opt);
        let result = if let Ok(mut commit) = commit_r {
            let parents = commit.parents.unwrap();
            if parents.len() > 1 || parents.is_empty() {
                println!("Discarding, parents {}", parents.len());
                GithubResult::Err(ErrorGithub::BadParents)
            } else {
                match parents[0].sha {
                    None => {
                        println!("Error error");
                        GithubResult::Err(ErrorGithub::ParentNotFound)
                    }
                    Some(ref sha) => {
                        match repos::new(&auth).get_commit(&self.data.1, &self.data.2, sha, popt){
                            Ok(mut parent_comm) => {
                                let reff = parent_comm.sha.take().unwrap();
                                let file_changed = commit.files.take().unwrap();
                                //TODO clean the files to the ones relate to the CVE patchset
                                let tuple = (
                                    self.data.0.clone(),
                                    self.data.3.clone(),
                                    file_changed
                                        .into_iter()
                                        .filter_map(|x| {
                                            let mut raw = x.raw_url.unwrap().replace("%2F", "/"); //Some repo return broken file paths.
                                            for i in self.data.4.iter(){
                                                if raw.ends_with(i) {return Some(raw);}
                                            }
                                            return None;
                                        })
                                        .collect(),
                                    reff,
                                );
                                println!("{:#?}", tuple);
                                GithubResult::Ok(tuple)
                            },
                            Err(err) => {
                                println!("Call failed with {:#?}", err);
                                GithubResult::Err(ErrorGithub::ParentNotFound)
                            }
                        }
                    }
                }
            }
        } else if let Err(ReposGetCommitError::Status404(err)) = commit_r {
            println!("Not found {:#?}", err);
            GithubResult::Err(ErrorGithub::NotFound)
        }
        else if let Err(ReposGetCommitError::Generic{code : 403}) = commit_r{
            println!("No request slots available");
            GithubResult::Err(ErrorGithub::ExhaustedRequest)
        }
        else {
            println!("Generic Error");
            GithubResult::Err(ErrorGithub::GenericError)
        };

        {
            *(self.result.lock().unwrap()) = Some(result);
        }
    }

    fn poll(&self)  -> PollResult<Self::Output>{
        if let Some(ref ret) = *self.result.lock().unwrap(){
            PollResult::Ready(ret.clone())
        }
        else {
            PollResult::Polling
        }
    }
}
#[derive(Clone)]
pub struct FutureWriter{
    data : (String, String, Vec<String>, String),
    output : String,
    compl : Arc<AtomicBool>,
}

impl FutureWriter {
    pub fn new(data :  (String, String, Vec<String>, String), output : String) -> FutureWriter{
        FutureWriter {data, output, compl : Arc::new(AtomicBool::new(false))}
    }
}

impl Promise for FutureWriter{
    type Output = ();
    fn poll(&self) -> PollResult<()>{
        if self.compl.load(Ordering::SeqCst) {
            PollResult::Ready(())
        } else {
            PollResult::Polling
        }
    }

    fn run(&self){
        let mut path = PathBuf::from(&self.output);
        path.push(&self.data.0);
        DirBuilder::new().recursive(true).create(&path).unwrap();
        path.push("post");
        DirBuilder::new().recursive(true).create(&path).unwrap();
        for url in self.data.2.iter().map(|x| Url::parse(x).unwrap()){
            let resp =  match ureq::get(url.as_str()).call(){
                Ok(resp) =>  resp,
                Err(err) => {
                    println!("Errore {:#?}  Retry",err);
                    match ureq::get(url.as_str()).call(){
                        Ok(resp) => resp,
                        Err(err) => {
                            println!("Errore {:#?}  Bailout",err);
                            continue;
                        }
                    }
                }
            };
            let mut cont = resp.into_string().unwrap();
            path.push(url.path_segments().unwrap().rev().next().unwrap());
            let mut f = File::create(&path).unwrap();
            f.write_all(&cont.into_bytes());
            path.pop();
  //         println!("{}", cont);
        }
        path.pop();
        path.push("pre");
        DirBuilder::new().recursive(true).create(&path).unwrap();
        for url in self.data.2.iter().map(|x| Url::parse(&x.replace(&self.data.1, &self.data.3)).unwrap()){
            let resp =  match ureq::get(url.as_str()).call(){
                Ok(resp) =>  resp,
                Err(err) => {
                    println!("Errore {:#?}  Retry",err);
                    match ureq::get(url.as_str()).call(){
                        Ok(resp) => resp,
                        Err(err) => {
                            println!("Errore {:#?}  Bailout",err);
                            continue;
                        }
                        //TODO filter file correctly with the CVE data. Better take data from the CVE itself
                    }
                }
            };
            let mut cont = resp.into_string().unwrap();
            path.push(url.path_segments().unwrap().rev().next().unwrap());
            let mut f = File::create(&path).unwrap();
            f.write_all(&cont.into_bytes());
  //         println!("{}", cont);
            path.pop();
        }

        self.compl.store(true, Ordering::SeqCst);
    }
}
//to pass and get thje comment mode from the function
#[derive(PartialEq,Debug)]
enum CommentMode {
    CommentModeOn,
    CommentModeOff,
}
//TODO declspec/attribute handling
/*
    A function is compoesd of a type, an identifier and a lst for agrs (type + id).
    The type can be preceed or followed by some specifiier (a macro, static, an attribute (__declspec  or __attribute__) )
*/

fn check_function_declaration<'a>(line : &'a str, prev_mode : CommentMode) -> (Option<&'a str>, CommentMode, bool ){
    let line = line.trim();
    let splitted = line.split_whitespace();
    let mut tokens = 0;
    let mut mismatch_comment = false;
    let mut prev_str = line;
    let mut comment_mode = prev_mode;
    let mut ignore_rest = false;
    let mut multiline_comment = false;
    let name = 'ret_for: {
        for mut split in splitted{
            if split.is_empty() {continue;}
            split = split.trim();
  //          println!("{:?}", split);

            if comment_mode == CommentMode::CommentModeOn {
                if split.ends_with("*/"){
                    comment_mode = CommentMode::CommentModeOff;
                    continue;
                }
                else if split.contains("*/") {
                    split = split.split("*/").collect::<Vec<&str>>()[1];
                    comment_mode = CommentMode::CommentModeOff;
                }
                else if split.ends_with("\""){
                    comment_mode = CommentMode::CommentModeOff;
                    continue;
                }
                else if split.contains("\"") {
                    split = split.split("\"").collect::<Vec<&str>>()[0];
                    comment_mode = CommentMode::CommentModeOff;
                }
                else {
                    continue;  //Skip the rest of the processing when in comment mode
                }
            }
            else {
                if split.ends_with("*/"){
                    comment_mode = CommentMode::CommentModeOff;
                    mismatch_comment = true;
                    continue;
                }
                else if split.contains("*/") {
                    mismatch_comment = true;
                    split = split.split("*/").collect::<Vec<&str>>()[1];
                    comment_mode = CommentMode::CommentModeOff;
                }            
            }
            if split.contains("//") && !split.starts_with("//") {
                split = split.split("//").collect::<Vec<&str>>()[0];
                ignore_rest = true; //the token start a single line comment, ignore the rest of the line after processing this part
            }
            if split.starts_with("/*"){
                comment_mode = CommentMode::CommentModeOn;
                continue;
            }
            if split.contains("/*") {
                split = split.split("/*").collect::<Vec<&str>>()[0];
                comment_mode = CommentMode::CommentModeOn;
            }
            if split.starts_with("\""){
                comment_mode = CommentMode::CommentModeOn;
                continue;
            }
            if split.contains("\"") {
                split = split.split("\"").collect::<Vec<&str>>()[0];
                comment_mode = CommentMode::CommentModeOn;
            }
         //   if split.starts_with
            if split.contains("=") || split.starts_with("//") || split.contains("{") || split.contains("}") || split.contains("<") || split.contains(">") || split.contains("!") || split.contains(","){
                break 'ret_for None; //Can't be a valid line for function definition
            }
            if split == "return" || split == "extern" ||  split.contains("#") || split == "asm"  ||  split == "_asm" || split == "__asm" || split == ":" || split == "if" || split == "else" || split == "case" {
                break 'ret_for None; //Can't be a valid line for function definition
            }
            if (split.contains("(") || split.starts_with("*") ) && tokens == 0 {
                break 'ret_for None; // ( can't be in the first token in the line. it would be a call in the form  name_func(...).
            }
            if split.contains("(") && tokens == 1 && split.starts_with("(") {
                break 'ret_for None; // ( would be the form nome_func (...)
            }
            if split.contains("(") && tokens >= 1 && !split.starts_with("(") && !split.ends_with(";"){
                break 'ret_for Some(split.split("(").collect::<Vec<&str>>()[0].trim_start_matches("*"));
            }
            if split.contains("(") && tokens >= 1 && split.starts_with("(") && !split.ends_with(";"){
                break 'ret_for Some(prev_str.trim_start_matches("*"));
            }
            if ignore_rest {break 'ret_for None}
            tokens += 1;
            prev_str = split;
        }
        None
    };
//    println!("{:?} {:?}",name, comment_mode);
    (name, comment_mode, mismatch_comment)
}


fn main() -> Result<(), io::Error> {
    let opts: Opts = Opts::parse();

    // Gets a value for config if supplied by user, or defaults to "default.conf"
    println!("Value for output: {}", opts.output);
    println!("Using input file: {}", opts.input);
    let cve = CVESearch::new(opts.threads);
    let mut walker = WalkDir::new(opts.input).into_iter();
    walker.next();
    DirBuilder::new().recursive(true).create(&opts.output).unwrap();
    let mut path_classifier = PathBuf::from(&opts.output);
    path_classifier.push("attributes.csv");
    let mut class_file = WriterBuilder::new().has_headers(false).from_path(&path_classifier)?;
    let mut tot = 0;
    let mut invalid = 0;
    let mut nonsingle = 0;
    let mut holders = Vec::new();
    for entry in walker {
        tot += 1;
        let entry = entry.unwrap();
        let mut file = File::open(entry.path())?;
        let mut interm = Vec::new();
        if file.read_to_end(&mut interm).is_err() {
            println!("{:?}", entry.path());
            invalid += 1;
            continue;
        }
        let mut contents = String::from_utf8_lossy(&interm).to_owned();
        let patches = Patch::from_single(&contents);
        match patches {
            Ok(patch) => {
                let mut names = Vec::new();
                for hunk in patch.hunks {
                    let mut comm_mode = CommentMode::CommentModeOff;
                    let mut name = None;
                    let mut found_name = false;
                    let mut name_used = false;
                    for line in hunk.lines {
                    // The context function in the range context data may refers to a previous function and not the function the modifications are made.
             //           println!("{:?}", line);
             //check for the declaration to be before the first edit in the chunk
                        let  tok :  (Option<&str>, CommentMode, bool) = match line {
                            Line::Add(line) => {
                                name_used = true;
                                //check_function_declaration(line, comm_mode);
                                (None, comm_mode, false)
                            },
                            Line::Remove(line) => {
                                name_used = true;
                                let (_,comm_mode, mismatch) = check_function_declaration(line, comm_mode);
                                (None, comm_mode, mismatch)// this may be useful instead
                            },
                            Line::Context(line) => {
                                check_function_declaration(line, comm_mode)
                            },
                        };
                        if tok.2 {
                            name = None;
                        }
                        comm_mode = tok.1;
                        match tok.0 {
                            Some(func) =>{
                                name_used = false;
                                name = Some(func);
                            },
                            None => {},
                        }
                    }
                    if name_used && name.is_some(){  //if not used use the context function
                        names.push(name.unwrap().to_owned());
                    }
                    else {
                        let hunk_t = hunk.range_text.clone();
                        let cont_name = check_function_declaration(&hunk_t,CommentMode::CommentModeOff).0;
                        if let Some(name) = cont_name {
                            let own = name.to_owned();
                            if !names.contains(&own){
                                names.push(own);
                            }
                        }
                    }
                }
                if names.is_empty() {
      //              println!("{:?}", entry.path());
                }
                else if names.len() == 1 {                    
                    holders.push((entry.clone(), names[0].clone(), vec![patch.old.path.strip_prefix("a/").unwrap().to_owned()]));
                }
                else{
                }
             //    break;
            //COSE
            },
            Err(err) => {
                match err {
                    ParseErrorOut::NoSinglePatch(_) => {
//                        println!("{}", entry.path().display());
                        nonsingle += 1;
                    },
                    ParseErrorOut::InnerError(err) => {
                        invalid +=1;
//                        println!("{:?}", entry.path());
//                        println!("{}", err);
                    }
                }
            }
        }
    }
    println!("{}  {}  {} {}", tot, holders.len(), nonsingle, invalid);
    let mut hold = Vec::new();
    for data in holders {
        let firssplit = data.0
            .file_name()
            .to_str()
            .unwrap()
            .rsplit_once('.')
            .unwrap()
            .0;
        //   if let None = firssplit {println!("{:?}", entry.file_name());}
        let splitting = firssplit.rsplit_once('-').unwrap();
        let cve_s = splitting.0;
        let commit = splitting.1;
        hold.push((
            cve_s.to_owned(),
            commit.to_owned(),
            cve.get_cve(cve_s.into()),
            data.2,
            data.1,
        ));
     //   if tot > 5 {break;}  //TODO test remove
    }
    let mut count = 0;
    let mut fail = 0;
    let mut lenght = hold.len();
    let mut retry = Vec::new();
    let mut repo_comm = Vec::new();
    let mut cves : Vec<String> = Vec::new();
    while lenght > 0 {
        let mut index = 0;
        //       println!("New Cycle, lenght {}", lenght);
        while index < lenght {
            let f = &mut hold[index];
            let res = f.2.poll();
            if let PollResult::Ready(vulres) = res {
                if let Ok(vul) = vulres {
                    let vul_obj = vul.as_object().unwrap();
                    let as_arr = vul_obj.get("references").unwrap().as_array().unwrap();
                    for url in as_arr {
                        let enc = Url::parse(url.as_str().unwrap()).unwrap();
                        if enc.host_str() == Some("github.com") {
                            let mut cwe = vul_obj.get("cwe");

                            let mut url_iter = enc.path_segments().unwrap().rev();
                            let last_element = url_iter.next().unwrap();
                            if last_element == f.1 {
                                count += 1;
                                url_iter.next(); // commit fragment
                                let repo = url_iter.next().unwrap().to_owned();
                                let user_org = url_iter.next().unwrap().to_owned();
                                let mut idx = 0;
                                for cve in &cves{
                                    if cve.starts_with(&f.0){idx += 1;}
                                }
                                let r_cve = if idx != 0{
                                    format!("{}-{}", f.0, idx)
                                }
                                else { f.0.clone() };
                                println!("{} {} {} {}", r_cve , user_org, repo, last_element);
                                if let Option::Some(cwei) = cwe {
                                    let  record = StringRecord::from(vec![r_cve.to_string(), cwei.to_string(), f.4.clone()]);
                                    class_file.write_record(&record);
                                }
                                repo_comm.push((r_cve, user_org, repo, f.1.clone(), f.3.clone()));
                                cves.push(f.0.clone());
                                break;
                            }
                        }
                    }
                    hold.remove(index);
                    lenght = hold.len();
                } else if let Err(err) = vulres {
                    fail += 1;
                    retry.push(hold.remove(index));
                    lenght = hold.len();
                    println!("{:?}", err);
                }
            } else {
                index += 1;
            }
        }
        for i in retry.drain(..) {
            hold.push((i.0.clone(), i.1, cve.get_cve(i.0), i.3.clone(), i.4.clone()));
        }
        lenght = hold.len();
    }
    println!(
        "Result : {} / {} / {} / {}",
        count, fail, invalid  + nonsingle, tot
    );

    class_file.flush();
    let executor : ThreadPoolExecutor<FutureGithub> = ThreadPoolExecutor::new(opts.threads);
    let mut github_cve_files_fut : Vec<FutureGithub> = Vec::new(); //(CVE, commit, filechanged, parent) in a future
    for i in repo_comm.iter() {
        let fut = FutureGithub::new(&opts.token, i);
        executor.submit(&fut);
        github_cve_files_fut.push(fut);
    }
    let mut github_cve_files = Vec::new();
    for i in github_cve_files_fut{
        if let GithubResult::Ok(ret) = i.get(){
            github_cve_files.push(ret);
        }
    }
    println!(
        "Good: {}, Error {}",
        github_cve_files.len(),
        repo_comm.len() - github_cve_files.len()
    );
    let executor_w : ThreadPoolExecutor<FutureWriter> = ThreadPoolExecutor::new(opts.threads);
    DirBuilder::new().recursive(true).create(&opts.output).unwrap();
    let mut taskwrite = Vec::new();
    for i in github_cve_files{
        let writetask = FutureWriter::new(i, opts.output.clone());
        executor_w.submit(&writetask);
        taskwrite.push(writetask);
    }
    for i in taskwrite{
        i.get();
    }
    Ok(())
}
