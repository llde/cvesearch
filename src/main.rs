extern crate cvesearch;
extern crate executor_future;
extern crate csv;

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

use csv::StringRecord;

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
    let mut class_file = csv::Writer::from_path(&path_classifier)?;
    let mut count = 0;
    let mut tot = 0;
    let mut invalid = 0;
    let mut nonc = 0;
    let mut fail = 0;
    let mut hold = Vec::new();
    for entry in walker {
        tot += 1;
        let entry = entry.unwrap();
        let mut file = File::open(entry.path())?;
        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_err() {
            invalid += 1; //Patch has non UTF8 chars
            continue;
        }
        let mut inv = true;
        let mut files= Vec::new();
        for line in contents.lines() {
            if let Some(stripped) = line.strip_prefix("--- "){
                if stripped == "/dev/null" {
                        nonc += 1; //File did not exist, don't consider this patch for now
                        inv = true;
                        break;
                }
            }
            if let Some(stripped) = line.strip_prefix("+++ ") {
                inv = false;
                if let Some((_, ext)) = stripped.rsplit_once('.') {
                    if ext != "c" && ext != "h" {
                        nonc += 1; //Patch has not only c and h file modification
                        inv = true;
                        break;
                    }
                }
                else { //TODO extensionless file can be readme/changelogs etc
                    nonc += 1; //Patch has not only c a nd h file modification
                    inv = true;
                    break;
                }
                println!("{:#?} {}",entry.file_name(),stripped);

                files.push(stripped.strip_prefix("b/").unwrap().to_owned());
            }
        }
        if inv {
            continue;
        }
        let firssplit = entry
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
            files,
        ));
     //   if tot > 5 {break;}  //TODO test remove
    }
    let mut lenght = hold.len();
    let mut retry = Vec::new();
    let mut repo_comm = Vec::new();
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
                    let mut cwe = vul_obj.get("cwe");
                    if let Option::Some(cwei) = cwe {
                        let  record = StringRecord::from(vec![f.0.to_string(), cwei.to_string()]);
                        class_file.write_record(&record);
                    }
                    for url in as_arr {
                        let enc = Url::parse(url.as_str().unwrap()).unwrap();
                        if enc.host_str() == Some("github.com") {
                            let mut url_iter = enc.path_segments().unwrap().rev();
                            let last_element = url_iter.next().unwrap();
                            if last_element == f.1 {
                                count += 1;
                                url_iter.next(); // commit fragment
                                let repo = url_iter.next().unwrap().to_owned();
                                let user_org = url_iter.next().unwrap().to_owned();
                                println!("{} {} {} {}", f.0, user_org, repo, last_element);
                                repo_comm.push((f.0.clone(), user_org, repo, f.1.clone(), f.3.clone()));
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
            hold.push((i.0.clone(), i.1, cve.get_cve(i.0), i.3.clone()));
        }
        lenght = hold.len();
    }
    println!(
        "Result : {} / {} / {} / {} / {}",
        count, fail, invalid, nonc, tot
    );


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
