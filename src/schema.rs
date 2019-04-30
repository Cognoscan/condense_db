use std::io;
use std::io::Error;
use std::io::ErrorKind::{InvalidData,Other};
use std::collections::HashMap;

use regex::Regex;

use super::{Hash, Integer, Timestamp};
use MarkerType;
use decode::*;


/// Struct holding the validation portions of a schema. Can be used for validation of a document or 
/// entry.
pub struct Schema {
    required: Vec<(String, Validator)>,
    optional: Vec<(String, Validator)>,
    entries: Vec<(String, Validator)>,
    types: HashMap<String, Validator>,
    field_type: Option<Validator>,
    unknown_ok: bool
}

impl Schema {
    pub fn from_raw(_raw: &[u8]) -> io::Result<Schema> {
        let required = Vec::new();
        let optional = Vec::new();
        let entries = Vec::new();
        let types = HashMap::new();
        let field_type = None;
        let unknown_ok = false;

        Ok(Schema {
            required,
            optional,
            entries,
            types,
            field_type,
            unknown_ok,
        })
    }

    /// Validates a document against this schema. Does not check the schema field itself.
    pub fn validate_doc(&self, doc: &mut &[u8]) -> io::Result<()> {
        let num_fields = match read_marker(doc)? {
            MarkerType::Object(len) => len,
            _ => return Err(Error::new(InvalidData, "Document wasn't an object")),
        };
        if num_fields == 0 && self.required.len() == 0 { return Ok(()); }

        // Setup for loop
        let mut req_index = 0;
        let mut opt_index = 0;
        let mut old_field = read_str(&mut doc.clone())?;
        let mut field: &str;
        // Main loop to check all fields
        for i in 0..num_fields {
            field = read_str(doc)?;
            // Check for proper lexicographic order of fields
            if i != 0 {
                if field <= old_field {
                    return Err(Error::new(InvalidData, "Repeated or improperly ordered fields in document"));
                }
            }
            old_field = field;

            // Check against required/optional/unknown types
            if Some(field) == self.required.get(req_index).map(|x| x.0.as_str()) {
                let validator = self.fetch_validator(&self.required[req_index].1);
                if let Err(e) = self.run_validator(self.required[req_index].0.as_str(), validator, doc) {
                    return Err(e);
                }
                req_index += 1;
            }
            else if Some(field) == self.optional.get(opt_index).map(|x| x.0.as_str()) {
                let validator = self.fetch_validator(&self.optional[opt_index].1);
                if let Err(e) = self.run_validator(self.optional[opt_index].0.as_str(), validator, doc) {
                    return Err(e);
                }
                opt_index += 1;
            }
            else if self.unknown_ok && self.field_type.is_some() {
            }
            else if self.unknown_ok {
                verify_value(doc)?;
            }
            else {
                return Err(Error::new(InvalidData, format!("Unknown, invalid field: \"{}\"", field)));
            }
        }

        if req_index >= self.required.len() {
            Ok(())
        }
        else {
            Err(Error::new(InvalidData,
                format!("Missing required fields, starting with {}", self.required[req_index].0.as_str())))
        }
    }

    fn fetch_validator<'a>(&'a self, v: &'a Validator) -> &'a Validator {
        if let &Validator::Type(ref s) = v {
            if let Some(ty) = self.types.get(s) {
                ty
            }
            else { &Validator::Invalid }
        }
        else { v }
    }

    fn run_validator(&self, field: &str, validator: &Validator, doc: &mut &[u8]) -> io::Result<()> {
        match validator {
            Validator::Invalid => Err(Error::new(InvalidData, format!("Field \"{}\" is always invalid", field))),
            Validator::Valid => Ok(()),
            Validator::Type(_) => Err(Error::new(Other,
                format!("Shouldn't happen: didn't get validator for Field \"{}\"", field))),
            Validator::Boolean(v) => {
                let value = read_bool(doc)?;
                match v.constant {
                    Some(b) => if b == value { Ok(()) } else { Err(Error::new(InvalidData,
                        format!("Field \"{}\" isn't set to {}", field, b))) },
                    None => Ok(()),
                }
            },
            Validator::Integer(v) => {
                let value = read_integer(doc)?;
                if value < v.min {
                    Err(Error::new(InvalidData,
                        format!("Field \"{}\" is {}, less than minimum of {}", field, value, v.min)))
                }
                else if value > v.max {
                    Err(Error::new(InvalidData,
                        format!("Field \"{}\" is {}, greater than maximum of {}", field, value, v.max)))
                }
                else if v.nin_vec.contains(&value) {
                    Err(Error::new(InvalidData,
                        format!("Field \"{}\" is {}, which is on the `nin` list", field, value)))
                }
                else if (v.in_vec.len() > 0) && !v.in_vec.contains(&value) {
                    Err(Error::new(InvalidData,
                        format!("Field \"{}\" is {}, which is not in the `in` list", field, value)))
                }
                else {
                    Ok(())
                }
            },
            _ => Err(Error::new(InvalidData, format!("Checking for field \"{}\" not implemented", field))),
        }
    }
}

enum Validator {
    Invalid,
    Valid,
    Type(String),
    Boolean(ValidBool),
    Integer(ValidInt),
    String(ValidStr),
    F32(ValidF32),
    F64(ValidF64),
    Binary(ValidBin),
    Array(ValidArray),
    Object(ValidObj),
    Hash(ValidHash),
    Lockbox(ValidLock),
    Timestamp(ValidTime),
}

struct ValidBool {
    constant: Option<bool>,
}

struct ValidInt {
    in_vec: Vec<Integer>,
    nin_vec: Vec<Integer>,
    min: Integer,
    max: Integer,
}

struct ValidStr {
    in_vec: Option<Vec<String>>,
    nin_vec: Option<Vec<String>>,
    constant: Option<String>,
    min_len: usize,
    max_len: usize,
    matches: Option<Box<Regex>>,
}

struct ValidF32 {
    in_vec: Option<Vec<f32>>,
    nin_vec: Option<Vec<f32>>,
    constant: Option<f32>,
    min: f32,
    max: f32,
    ex_min: bool,
    ex_max: bool,
}

struct ValidF64 {
    in_vec: Option<Vec<f64>>,
    nin_vec: Option<Vec<f64>>,
    constant: Option<f64>,
    min: f64,
    max: f64,
    ex_min: bool,
    ex_max: bool,
}

struct ValidBin {
    in_vec: Option<Vec<Vec<u8>>>,
    nin_vec: Option<Vec<Vec<u8>>>,
    constant: Option<Vec<u8>>,
    min_len: Option<usize>,
    max_len: Option<usize>,
}

struct ValidArray {
    /// Raw msgpack to compare against
    constant: Option<Vec<u8>>,
    in_vec: Option<Vec<Vec<u8>>>,
    nin_vec: Option<Vec<Vec<u8>>>,
    min_len: usize,
    max_len: usize,
    items: Vec<Validator>,
    extra_items: Option<Box<Validator>>,
    contains: Vec<Validator>,
    unique: bool,
}

struct ValidObj {
    constant: Option<Vec<u8>>,
    in_vec: Option<Vec<Vec<u8>>>,
    nin_vec: Option<Vec<Vec<u8>>>,
    required: Vec<(String, Validator)>,
    optional: Vec<(String, Validator)>,
    min_fields: usize,
    max_fields: usize,
    field_type: Box<Validator>,
    unknown_ok: bool
}

struct ValidHash {
    constant: Option<Hash>,
}

struct ValidLock {
    max_len: usize,
}

struct ValidTime {
    constant: Option<Timestamp>,
    in_vec: Vec<Timestamp>,
    nin_vec: Vec<Timestamp>,
    min: Timestamp,
    max: Timestamp,
    ex_min: bool,
    ex_max: bool,
}






