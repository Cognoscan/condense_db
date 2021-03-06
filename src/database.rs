//! Internal Database
//! =================
//!
//! The internal database is a set of 4 key-value stores:
//!
//! - data: Documents and entries
//! - ttl: Timestamps for documents/entries
//! - root: Flat list of "root" documents
//! - reference: Counts of references to a document
//!
//! Documents in the database are tracked by reference-counting. This provides a semi-intuitive way 
//! to manage documents without needing to create a complete hierarchy. There are two types of 
//! references: "strong" references and "weak" references. Both are hash links, but their context 
//! determines if they are strong or weak:
//!
//! - Strong references are hashes in a document, or hashes in an entry that are required for it to 
//! satisfy a document schema.
//! - Weak references are hashes in an entry that aren't required to satisfy a document schema.
//!
//! ### Adding a document
//!
//! The document is first checked to make sure it may be added:
//!
//! 1. It is checked against its schema
//! 2. `root` is checked to make sure the name is unique, if it is a root document.
//!
//! The database is then updated in the following way:
//! 1. `data` is updated: the key is the document hash, the value is the raw document.
//! 2. `reference` is updated: the key is the document hash. It contains u32 counters: one for 
//!    counting references from `root`, one for counting references from documents/entries that 
//!    require it, and one for counting all other references.
//! 3. `reference` is updated: the schema used by the document has its reference counter 
//!    incremented by 1.
//! 3. `root` is updated: if the document is a root document, it is added here. The key is the 
//!    unique name, and the value is the document hash.
//! 4. `ttl` is updated. The time to live is converted to a timestamp and used as a key. The length 
//!    of the document hash, along with the hash itself, is appended to the value at that key.
//!
//! ### Deleting a Document
//!
//! Documents (and their entries) are automatically removed if there are no references to it from 
//! `root` AND one of the following is true:
//!
//! 1. TTL has expired and the requirement counter in `reference` is 0.
//! 2. TTL has expired and it cannot be reached through required hash links from root documents & 
//!    their entries.
//! 3. It cannot be reached through any hash links, required or otherwise.
//!
//! This should make document deletion relatively easy for the user. Essential documents will 
//! always stick around, while they can be managed by changing TTL and whether they are in `root` 
//! or not.
//!
//! Deletion Strategy
//! -----------------
//!
//! Deletion from `root` updates the `reference` counters. A document is immediately deleted if the 
//! reference counters are 0 afterwards. The entries are then immediately deleted and the reference 
//! counters for them are updated, at which point deletion halts. If any reference counters are all 
//! 0, document deletion is scheduled for the future.
//!
//! Periodically, the database will try to delete data. It will first go through any deletion 
//! already scheduled, update things accordingly, and finish if things were deleted. If there are 
//! no deletions scheduled, it will run a tracing garbage collection algorithm on remaining 
//! non-root objects.
//!
//! Every couple of minutes, the database will run through the `ttl` list and attempt to delete 
//! stale documents & entries. If a document cannot be deleted due to non-zero reference counters, 
//! it will be marked for deletion the moment the strong references are removed.
//!



use std::collections::HashMap;
use crossbeam_channel::{TrySendError, TryRecvError, RecvError, Sender, Receiver, unbounded, bounded, Select};
use std::path::Path;

use super::{Schema, Permission, Query, Hash, Document, Entry};
use document;

/// Types of changes that can be made to the database.
enum ChangeRequest {
    /// Add a document to the databse.
    AddDoc((Document, Permission, u32)),
    /// Remove a document from the database by hash.
    DelDoc(Hash),
    /// Add an entry to the database.
    AddEntry((Entry, u32)),
    /// Remove an entry from the database by hash of document & entry.
    DelEntry((Hash, Hash)),
    /// Remove documents/entries that match the query given.
    DelQuery(Query),
    /// Set time-to-live for a given document.
    SetTtlDoc((Hash, u32)),
    /// Set time-to-live for a given entry, by hash of document & entry.
    SetTtlEntry((Hash, Hash, u32)),
}

/// Result of any changes requested of the database.
#[derive(PartialEq, Debug)]
pub enum ChangeResult {
    /// Change made successfuly.
    Ok,
    /// Failed for unknown reasons, likely due to underlying database
    Failed,
    /// Couldn't operate on a document because it doesn't exist. Also returned if adding an entry 
    /// to a non-existent document, or querying a non-existent document.
    NoSuchDoc,
    /// Couldn't operate on an entry because it doesn't exist.
    NoSuchEntry,
    /// Couldn't delete a schema document because it is in use.
    SchemaInUse,
    /// Couldn't delete a certificate because it is in use.
    CertInUse,
    /// Document/Entry failed schema check when being added.
    FailedSchemaCheck,
    /// Couldn't find schema referenced by the document.
    SchemaNotFound,
    /// Document tried to use a non-schema document as its schema.
    NotValidSchema,
    /// Query didn't match schema of the document(s) being operated on.
    InvalidQuery,
}

/// Control operations on the database. For housekeeping and starting/stopping the database.
enum DbControl {
    Stop,
}

/// A bundled query request for the system
struct QueryRequest {
    pub query:  Query,
    pub permission: Permission,
}

/// Possible responses to a query.
pub enum QueryResponse {
    /// A document matching the query, along with the relative effort spent retrieving it.
    Doc((Document, i32)),
    /// An entry matching the query, along with the relative effort spent retrieving it.
    Entry((Entry, i32)),
    /// Query has been exhausted. Only occurs for queries made to retrive a set list of documents. 
    /// The query channel is closed after this.
    DoneForever,
    /// Query failed to match the schema for all given documents. The query channel is closed after 
    /// this.
    Invalid,
    /// One of the documents retrieved failed schema validation.
    BadDoc(Hash),
    /// One of the documents retrieved used an unknown schema. First Hash is the document, second 
    /// hash is the Schema.
    UnknownSchema((Hash, Hash)),
}

/// Database for holding documents and associated entries. Tracks schema, handles queries.
pub struct Db {
    handle: std::thread::JoinHandle<()>,
    control_in: Sender<DbControl>,
    change_in: Sender<(ChangeRequest, Sender<ChangeResult>)>,
    query_in: Sender<(QueryRequest, Sender<QueryResponse>, Receiver<()>)>,
}

impl Db {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Db, String> {
        let (control_in, control_out) = unbounded();
        let (change_in, change_out) = unbounded();
        let (query_in, query_out) = unbounded();
        let db = rocksdb::DB::open_default(path).map_err(|e| e.into_string())?;
        let handle = std::thread::spawn(move || db_loop(db, control_out, change_out, query_out));
        Ok(Db {
            handle,
            control_in,
            change_in,
            query_in
        })
    }

    /// Submit a change request to the database. Returns a `ChangeWait`, which will eventually 
    /// contain the result of the change operation.
    fn make_change(&self, change: ChangeRequest) -> Result<ChangeWait, ()> {
        let (result_in, result_out) = bounded(1);
        self.change_in.send((change, result_in)).map_err(|_e| ())?;
        Ok(ChangeWait { chan: result_out })
    }

    /// Close out the database and safely exit. Blocks until the thread finishes. Returns an error 
    /// if the thread panicked or the control handle was already closed.
    pub fn close(self) -> Result<(), ()> {
        self.control_in.send(DbControl::Stop).map_err(|_e| ())?;
        self.handle.join().map_err(|_e| ())
    }

    /// Add a document to the database. Returns a `ChangeWait` if request is successfuly made.
    /// The `ChangeWait` will return `Ok` if the document is added, or if the document already 
    /// exists in the database. If the document already exists, it will be changed to have the 
    /// permissions and time-to-live set by this call.
    pub fn add_doc(&self, doc: Document, perm: &Permission, ttl: u32) -> Result<ChangeWait, ()> {
        self.make_change(ChangeRequest::AddDoc((doc, perm.clone(), ttl)))
    }

    /// Remove a document from the database, based on its hash. Returns a `ChangeWait` if request 
    /// is successfully made.
    pub fn del_doc(&self, hash: Hash) -> Result<ChangeWait, ()> {
        self.make_change(ChangeRequest::DelDoc(hash))
    }

    /// Add an entry into the database. Returns a `ChangeWait` if request is successfully made.
    /// The `ChangeWait` will return `Ok` if the entry is added, or if the entry already exists in 
    /// the database. If the entry already exists, it will be changed to have the time-to-live set 
    /// by this call.
    pub fn add_entry(&self, entry: Entry, ttl: u32) -> Result<ChangeWait, ()> {
        self.make_change(ChangeRequest::AddEntry((entry, ttl)))
    }

    /// Remove an entry from the database. Returns a `ChangeWait` if request is successfully made.
    pub fn del_entry(&self, doc_hash: Hash, entry_hash: Hash) -> Result<ChangeWait, ()> {
        self.make_change(ChangeRequest::DelEntry((doc_hash, entry_hash)))
    }

    /// Delete documents and/or entries that match a given query.
    pub fn del_query(&self, query: Query) -> Result<ChangeWait, ()> {
        self.make_change(ChangeRequest::DelQuery(query))
    }

    /// Change the time-to-live (TTL) of a document.
    pub fn set_ttl_doc(&self, doc: Hash, ttl: u32) -> Result<ChangeWait, ()> {
        self.make_change(ChangeRequest::SetTtlDoc((doc, ttl)))
    }

    /// Change the time-to-live (TTL) of an entry.
    pub fn set_ttl_entry(&self, doc: Hash, entry: Hash, ttl: u32) -> Result<ChangeWait, ()> {
        self.make_change(ChangeRequest::SetTtlEntry((doc, entry, ttl)))
    }

    pub fn query(&self, query: Query, perm: &Permission, capacity: usize) -> Result<QueryWait, ()> {
        if capacity == 0 { return Err(()); }
        let (result_in, result_out) = bounded(capacity);
        let (done, quit) = bounded(0); // Channel to drop when the query maker is done
        let request = QueryRequest { query: query, permission: perm.clone() };
        self.query_in.send((request, result_in, quit)).map_err(|_e| ())?;
        Ok(QueryWait { chan: result_out, done: done })
    }

}

/// A channel that receives the result of a change request.
pub struct ChangeWait {
    chan: Receiver<ChangeResult>
}

impl ChangeWait {
    /// Block until the database change request completes. Errors if the change result has been 
    /// received already, or if the database process died.
    pub fn recv(self) -> Result<ChangeResult, RecvError> {
        self.chan.recv()
    }

    /// Check to see if the change request has completed. Errors if channel is not ready, or if the 
    /// channel disconnected.
    pub fn try_recv(&self) -> Result<ChangeResult, TryRecvError> {
        self.chan.try_recv()
    }
}

pub struct QueryWait {
    chan: Receiver<QueryResponse>,
    done: Sender<()>
}

impl QueryWait {
    /// Block until a query response occurs. Errors if the database closed the channel, which 
    /// happens if the database stopped or if the database has already sent `DoneForever` or 
    /// `Invalid` responses.
    pub fn recv(&self) -> Result<QueryResponse, RecvError> {
        self.chan.recv()
    }

    /// Check to see if any query results showed up. Errors if channel is not ready, or if the 
    /// channel is closed. Channel is closed if the database stopped, or if the database has 
    /// already sent `DoneForever` or `Invalid` responses.
    pub fn try_recv(&self) -> Result<QueryResponse, TryRecvError> {
        self.chan.try_recv()
    }
}

struct InternalDb {
    /// The core database
    rocks_db: rocksdb::DB,
    /// The document database
    doc_db: HashMap<Hash,(usize, Vec<u8>,Permission,u32)>,
    /// The database of entries
    entry_db: HashMap<Hash, Vec<(String,Vec<u8>,u32)>>,
    /// Tracking how many places a given schema is used.
    schema_tracking: HashMap<Hash, usize>,
}

impl InternalDb {
    fn new(rocks_db: rocksdb::DB) -> InternalDb {
        InternalDb {
            rocks_db,
            doc_db: HashMap::new(),
            entry_db: HashMap::new(),
            schema_tracking: HashMap::new(),
        }
    }

    fn make_change(&mut self, change: ChangeRequest) -> ChangeResult {
        match change {
            ChangeRequest::AddDoc((doc, perm, ttl)) => {
                let hash = doc.hash();
                if !self.doc_db.contains_key(&hash) {
                    let doc_len = doc.doc_len();
                    let doc = doc.to_vec();
                    // extract_schema_hash verifies the document is a msgpack object & gets the schema.
                    let result = match document::extract_schema_hash(&doc[..]) {
                        Ok(Some(schema_hash)) => {
                            match self.doc_db.get(&schema_hash) {
                                Some((_,schema,_,_)) => {
                                    // Get the schema and verify the document
                                    let schema_result = Schema::from_raw(&mut &schema[..]);
                                    if let Ok(verifier) = schema_result {
                                        if let Ok(_) = verifier.validate_doc(&mut &doc[..]) {
                                            // Increment the schema tracking count
                                            self.schema_tracking.entry(schema_hash.clone())
                                                .and_modify(|v| *v += 1)
                                                .or_insert(1);
                                            ChangeResult::Ok
                                        }
                                        else {
                                            ChangeResult::FailedSchemaCheck
                                        }
                                    }
                                    else {
                                        ChangeResult::NotValidSchema
                                    }
                                },
                                None => {
                                    ChangeResult::SchemaNotFound
                                }
                            }
                        }
                        Ok(None) => {
                            ChangeResult::Ok
                        }
                        Err(_) => ChangeResult::FailedSchemaCheck, // Failed because it wasn't even a proper document
                    };
                    if result == ChangeResult::Ok {
                        self.doc_db.insert(hash, (doc_len, doc, perm, ttl));
                    }
                    result
                }
                else {
                    ChangeResult::Ok
                }
            },
            ChangeRequest::DelDoc(hash) => {
                let result = match self.doc_db.get(&hash) {
                    Some((_,doc,_,_)) => {
                        if let Ok(Some(schema_hash)) = document::extract_schema_hash(&doc[..]) {
                            self.schema_tracking.entry(schema_hash)
                                .and_modify(|v| *v -= 1);
                        };
                        match self.schema_tracking.get(&hash) {
                            Some(count) => {
                                if *count > 0 {
                                    ChangeResult::SchemaInUse
                                }
                                else {
                                    ChangeResult::Ok
                                }
                            },
                            None => ChangeResult::Ok,
                        }
                    },
                    None => ChangeResult::NoSuchDoc,
                };
                if result == ChangeResult::Ok {
                    self.doc_db.remove(&hash);
                    self.entry_db.remove(&hash);
                }
                result
            },
            ChangeRequest::AddEntry((entry, ttl)) => {
                let (doc_hash, field, entry) = entry.to_parts();
                let result = self.doc_db.get(&doc_hash);
                if result.is_none() { return ChangeResult::NoSuchDoc; }
                let (_,doc,_,_) = result.unwrap();
                if let Some(schema_hash) = document::extract_schema_hash(&doc[..])
                    .expect(&format!("Corrupted Database: Document wasn't a valid document: {:X?}", doc_hash))
                {
                    let (_,schema,_,_) = self.doc_db
                        .get(&schema_hash)
                        .expect(&format!("Corrupted Database: Document's schema is missing: {:X?}", schema_hash));
                    let schema = Schema::from_raw(&mut &schema[..])
                        .expect(&format!("Corrupted Database: Schema that was added can't be read: {:X?}", schema_hash));

                    // Validate against retrieved schema
                    let checklist = schema.validate_entry(&field, &mut &entry[..]);
                    if checklist.is_err() { return ChangeResult::FailedSchemaCheck; }
                    let checklist = checklist.unwrap();

                    // Go through all items in the checklist created by the schema
                    if checklist.iter().all(|(hash, list)| {
                        if let Some((_,doc,_,_)) = self.doc_db.get(&hash) {
                            list.iter().all(|index| schema.validate_checklist_item(*index, &mut &doc[..]).is_ok())
                        }
                        else {
                            false
                        }
                    })
                    {
                        self.entry_db.entry(doc_hash)
                            .or_insert(Vec::with_capacity(1)) 
                            .push((field, entry, ttl));
                        ChangeResult::Ok
                    }
                    else {
                        ChangeResult::FailedSchemaCheck
                    }
                }
                else {
                    self.entry_db.entry(doc_hash)
                        .or_insert(Vec::with_capacity(1)) 
                        .push((field, entry, ttl));
                    ChangeResult::Ok
                }
            }
            ChangeRequest::DelEntry(_)      => ChangeResult::Failed,
            ChangeRequest::DelQuery(_)      => ChangeResult::Failed,
            ChangeRequest::SetTtlDoc(_)     => ChangeResult::Failed,
            ChangeRequest::SetTtlEntry(_)   => ChangeResult::Failed,
        }
    }

    /// Retrieve a document. If decoding the document fails, return nothing & assume it is 
    /// corrupted.
    fn get_doc(&self, hash: &Hash, _perm: &Permission) -> Option<Document> {
        match self.doc_db.get(hash) {
            Some(storage) => {
                let doc = storage.1.clone();
                match super::document::from_raw(hash, doc, storage.0) {
                    Ok(doc) => Some(doc),
                    Err(_) => None,
                }
            },
            None => None,
        }
    }
}

struct OpenQuery {
    root: Hash,
    perm: Permission,
    channel: Sender<QueryResponse>,
    quit: Receiver<()>,
    root_in_db: bool,
    root_sent: bool,
    active: bool,
}

impl OpenQuery {
    fn new(root: Hash, perm: Permission, channel: Sender<QueryResponse>, quit: Receiver<()>) -> OpenQuery {
        OpenQuery {
            root,
            perm,
            channel,
            quit, 
            root_in_db: true,
            root_sent: false,
            active: true,
        }
    }

    fn channel_full(&self) -> bool {
        self.channel.is_full()
    }

    fn get_in_db(&self) -> bool {
        self.root_in_db
    }

    fn set_in_db(&mut self, in_db: bool) {
        self.root_in_db = in_db;
    }

    fn get_root(&self) -> &Hash {
        &self.root
    }

    fn is_root_sent(&self) -> bool {
        self.root_sent
    }

    fn root_sent(&mut self) {
        self.root_sent = true;
    }

    fn get_perm(&self) -> &Permission {
        &self.perm
    }

    fn finish(&mut self) {
        self.active = false;
    }

    fn try_send(&self, response: QueryResponse) -> Result<(), TrySendError<QueryResponse>> {
        self.channel.try_send(response)
    }

    /// Returns true if the query cannot return anything yet
    fn not_ready(&self) -> bool {
        !self.active || self.channel_full() || !self.get_in_db()
    }

    /// Run the query on the database. This will push either nothing to the response channel, or a 
    /// single response. It never pushes multiple responses in a single call.
    fn run(&mut self, db: &InternalDb) {
        // Check to see if query is still open, and halt if it isn't
        self.active = match self.quit.try_recv() {
            Err(e) => {
                !e.is_disconnected()
            }
            _ => true
        };
        if !self.active { return; }

        if self.is_root_sent() {
            if let Ok(()) = self.try_send(QueryResponse::DoneForever) {
                self.finish();
            }
        }
        match db.get_doc(self.get_root(), self.get_perm()) {
            Some(doc) => {
                if let Ok(()) = self.try_send(QueryResponse::Doc((doc, 0))) {
                    self.root_sent();
                };
            },
            None => { self.set_in_db(false); }
        };
    }
}

/// The primary event loop for the database. The actual database handles change requests, queries, 
/// and management in this loop, which should be running in its own thread. It will block until one 
/// of the following conditions are met:
///
/// - A query response channel goes from full to open / disconnected.
/// - A change request has been made
/// - A database management command has been issued
/// 
fn db_loop(
    rocks_db: rocksdb::DB,
    control: Receiver<DbControl>,
    change: Receiver<(ChangeRequest, Sender<ChangeResult>)>,
    query_inbox: Receiver<(QueryRequest, Sender<QueryResponse>, Receiver<()>)>)
{
    let mut db = InternalDb::new(rocks_db);
    let mut done = false;

    // Queries to respond to. Contains iterators, response channel, and bool to indicate the query 
    // is active
    let mut open_queries: Vec<OpenQuery> = Vec::new();
    
    // Set up the channel selector
    let mut select = Select::new();
    let index_ctrl = select.recv(&control);
    let index_change = select.recv(&change);
    let index_query = select.recv(&query_inbox);

    // Main loop
    loop {
        let mut active = false;
        if let Ok(oper) = select.try_select() {
            active = true;
            match oper.index() {
                i if i == index_ctrl => {
                    let cmd = oper.recv(&control);
                    match cmd {
                        Err(_) => done = true, // Halt if command channel was closed
                        Ok(cmd) => {
                            match cmd {
                                DbControl::Stop => done = true,
                            }
                        }
                    };
                },
                i if i == index_change => {
                    if let Ok((cmd, resp)) = oper.recv(&change) {
                        // Get document hash if document is being added
                        let (add_doc, hash) = if let ChangeRequest::AddDoc((ref doc,_,_)) = cmd {
                            (true, doc.hash())
                        }
                        else {
                            (false, Hash::new_empty())
                        };
                        // Make change to database
                        let result = db.make_change(cmd);
                        // Check for open queries on this document & update as appropriate
                        if (result == ChangeResult::Ok) && add_doc {
                            for query in open_queries.iter_mut() {
                                if *query.get_root() == hash { query.set_in_db(true); }
                            }
                        }
                        // Send the response. If nothing is at the other end, we don't care.
                        resp.send(result).unwrap_or(());
                    }
                },
                i if i == index_query => {
                    if let Ok((query, resp, quit)) = oper.recv(&query_inbox) {
                        for root in query.query.root_iter() {
                            open_queries.push(OpenQuery::new(root.clone(), query.permission.clone(), resp.clone(), quit.clone()));
                        }
                    }
                }
                _ => unreachable!(),
            }
        }

        for query in open_queries.iter_mut() {
            if query.not_ready() { continue; }
            query.run(&db);
            active = true; // Set as long as we keep servicing at least one query
        }

        // Drop completed queries
        open_queries.retain(|query| query.active);

        if done {
            break;
        }

        // Yield to the OS if the database is idling
        if !active {
            std::thread::yield_now();
        }
    };
}


