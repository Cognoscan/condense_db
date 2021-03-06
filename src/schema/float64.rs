use std::io;
use std::io::Error;
use std::io::ErrorKind::InvalidData;
use std::f64;
use std::cmp::Ordering;

use byteorder::{ReadBytesExt, BigEndian};
use ieee754::Ieee754;

use decode::*;
use super::{MAX_VEC_RESERVE, sorted_union, sorted_intersection, Validator};
use marker::MarkerType;

/// F64 type validator
#[derive(Clone,Debug)]
pub struct ValidF64 {
    in_vec: Vec<f64>,
    nin_vec: Vec<f64>,
    min: f64,
    max: f64,
    nan_ok: bool,
    query: bool,
    ord: bool,
    ex_min: bool, // setup only
    ex_max: bool, // setup only
}

impl ValidF64 {
    pub fn new(is_query: bool) -> ValidF64 {
        ValidF64 {
            in_vec: Vec::with_capacity(0),
            nin_vec: Vec::with_capacity(0),
            min: f64::NEG_INFINITY,
            max: f64::INFINITY,
            nan_ok: true,
            query: is_query,
            ord: is_query,
            ex_min: false,
            ex_max: false,
        }
    }

    pub fn from_const(constant: f64, is_query: bool) -> ValidF64 {
        let mut v = ValidF64::new(is_query);
        let mut in_vec = Vec::with_capacity(1);
        in_vec.push(constant);
        v.in_vec = in_vec;
        v
    }

    /// Update the validator. Returns `Ok(true)` if everything is read out Ok, `Ok(false)` if we 
    /// don't recognize the field type or value, and `Err` if we recognize the field but fail to 
    /// parse the expected contents. The updated `raw` slice reference is only accurate if 
    /// `Ok(true)` was returned.
    pub fn update(&mut self, field: &str, raw: &mut &[u8]) -> io::Result<bool> {
        // Note about this match: because fields are lexicographically ordered, the items in this 
        // match statement are either executed sequentially or are skipped.
        match field {
            "default" => {
                read_f64(raw)?;
                Ok(true)
            }
            "ex_max" => {
                self.ex_max = read_bool(raw)?;
                self.max = self.max.prev();
                self.nan_ok = false;
                Ok(true)
            },
            "ex_min" => {
                self.ex_min = read_bool(raw)?;
                self.min = self.min.next();
                self.nan_ok = false;
                Ok(true)
            },
            "in" => {
                match read_marker(raw)? {
                    MarkerType::F64 => {
                        let v = raw.read_f64::<BigEndian>()?;
                        self.in_vec.reserve_exact(1);
                        self.in_vec.push(v);
                    },
                    MarkerType::Array(len) => {
                        self.in_vec.reserve_exact(len.min(MAX_VEC_RESERVE));
                        for _i in 0..len {
                            self.in_vec.push(read_f64(raw)?);
                        };
                        self.in_vec.sort_unstable_by(|a,b| a.total_cmp(b));
                        self.in_vec.dedup();
                    },
                    _ => {
                        return Err(Error::new(InvalidData, "F64 validator expected array or constant for `in` field"));
                    },
                }
                Ok(true)
            },
            "max" => {
                let max = read_f64(raw)?;
                if max.is_nan() {
                    Err(Error::new(InvalidData, "F64 validator does not accept NaN for `max` field"))
                }
                else if self.ex_max && (max == f64::NEG_INFINITY) {
                    Ok(false)
                }
                else {
                    self.nan_ok = false;
                    self.max = if self.ex_max { max.prev() } else { max };
                    Ok(true)
                }
            }
            "min" => {
                let min = read_f64(raw)?;
                if min.is_nan() {
                    Err(Error::new(InvalidData, "F64 validator does not accept NaN for `min` field"))
                }
                else if self.ex_min && (min == f64::INFINITY) {
                    Ok(false)
                }
                else {
                    self.nan_ok = false;
                    self.min = if self.ex_min { min.next() } else { min };
                    Ok(self.min <= self.max)
                }
            }
            "nin" => {
                match read_marker(raw)? {
                    MarkerType::F64 => {
                        let v = raw.read_f64::<BigEndian>()?;
                        self.nin_vec.reserve_exact(1);
                        self.nin_vec.push(v);
                    },
                    MarkerType::Array(len) => {
                        self.nin_vec.reserve_exact(len.min(MAX_VEC_RESERVE));
                        for _i in 0..len {
                            self.nin_vec.push(read_f64(raw)?);
                        };
                        self.nin_vec.sort_unstable_by(|a,b| a.total_cmp(b));
                        self.nin_vec.dedup();
                    },
                    _ => {
                        return Err(Error::new(InvalidData, "F64 validator expected array or constant for `nin` field"));
                    },
                }
                Ok(true)
            }
            "ord" => {
                self.ord = read_bool(raw)?;
                Ok(true)
            }
            "query" => {
                self.query = read_bool(raw)?;
                Ok(true)
            }
            "type" => if "F64" == read_str(raw)? { Ok(true) } else { Err(Error::new(InvalidData, "Type doesn't match F64")) },
            _ => Err(Error::new(InvalidData, "Unknown fields not allowed in f64 validator")),
        }
    }

    /// Final check on the validator. Returns true if at least one value can still pass the 
    /// validator.
    pub fn finalize(&mut self) -> bool {
        if self.in_vec.len() > 0 {
            let mut in_vec: Vec<f64> = Vec::with_capacity(self.in_vec.len());
            let mut nin_index = 0;
            for val in self.in_vec.iter() {
                while let Some(nin) = self.nin_vec.get(nin_index) {
                    if nin.total_cmp(val) == Ordering::Less { nin_index += 1; } else { break; }
                }
                if let Some(nin) = self.nin_vec.get(nin_index) {
                    if nin.total_cmp(val) == Ordering::Equal { continue; }
                }
                if self.nan_ok {
                    in_vec.push(*val);
                }
                else if !val.is_nan() && (*val >= self.min) && (*val <= self.max) {
                    in_vec.push(*val);
                }
            }
            in_vec.shrink_to_fit();
            self.in_vec = in_vec;
            self.nin_vec = Vec::with_capacity(0);
            self.in_vec.len() > 0
        }
        else {
            let min = self.min;
            let max = self.max;
            let nan_ok = self.nan_ok;
            // Only keep `nin` values that would otherwise pass
            self.nin_vec.retain(|val| {
                nan_ok || (!val.is_nan() && (*val >= min) && (*val <= max))
            });
            self.nin_vec.shrink_to_fit();
            true
        }
    }

    pub fn validate(&self, field: &str, doc: &mut &[u8]) -> io::Result<()> {
        let value = read_f64(doc)?;
        if (self.in_vec.len() > 0) && self.in_vec.binary_search_by(|probe| probe.total_cmp(&value)).is_err() {
            Err(Error::new(InvalidData,
                format!("Field \"{}\" is {}, which is not in the `in` list", field, value)))
        }
        else if self.in_vec.len() > 0 {
            println!("Passed in_vec test with {}", value);
            Ok(())
        }
        else if value.is_nan() && !self.nan_ok
        {
            Err(Error::new(InvalidData,
                format!("Field \"{}\" is NaN and therefore out of range", field)))
        }
        else if !self.nan_ok && (value < self.min) {
            Err(Error::new(InvalidData,
                format!("Field \"{}\" is {}, less than minimum of {}", field, value, self.min)))
        }
        else if !self.nan_ok && (value > self.max) {
            Err(Error::new(InvalidData,
                format!("Field \"{}\" is {}, greater than maximum of {}", field, value, self.max)))
        }
        else if self.nin_vec.binary_search_by(|probe| probe.total_cmp(&value)).is_ok() {
            Err(Error::new(InvalidData,
                format!("Field \"{}\" is {}, which is on the `nin` list", field, value)))
        }
        else {
            Ok(())
        }

    }

    /// Intersection of F64 with other Validators. Returns Err only if `query` is true and the 
    /// other validator contains non-allowed query parameters.
    pub fn intersect(&self, other: &Validator, query: bool) -> Result<Validator, ()> {
        if query && !self.query && !self.ord { return Err(()); }
        match other {
            Validator::F64(other) => {
                if query && (
                    (!self.query && (!other.in_vec.is_empty() || !other.nin_vec.is_empty()))
                    || (!self.ord && !other.nan_ok))
                {
                    Err(())
                }
                else if !self.nan_ok && !other.nan_ok && ((self.min > other.max) || (self.max < other.min)) {
                    Ok(Validator::Invalid)
                }
                else {
                    let in_vec = if (self.in_vec.len() > 0) && (other.in_vec.len() > 0) {
                        sorted_intersection(&self.in_vec[..], &other.in_vec[..], |a,b| a.total_cmp(b))
                    }
                    else if self.in_vec.len() > 0 {
                        self.in_vec.clone()
                    }
                    else {
                        other.in_vec.clone()
                    };
                    if in_vec.len() == 0 && (self.in_vec.len()+other.in_vec.len() > 0) {
                        return Ok(Validator::Invalid);
                    }
                    let mut new_validator = ValidF64 {
                        in_vec: in_vec,
                        nin_vec: sorted_union(&self.nin_vec[..], &other.nin_vec[..], |a,b| a.total_cmp(b)),
                        min: self.min.max(other.min),
                        max: self.max.min(other.max),
                        nan_ok: self.nan_ok && other.nan_ok,
                        query: self.query && other.query,
                        ord: self.ord && other.ord,
                        ex_min: false, // Doesn't get used by this point - for setup of validator only.
                        ex_max: false, // Doesn't get used by this point - for setup of validator only.
                    };
                    let valid = new_validator.finalize();
                    if !valid {
                        Ok(Validator::Invalid)
                    }
                    else {
                        Ok(Validator::F64(new_validator))
                    }
                }
            },
            Validator::Valid => Ok(Validator::F64(self.clone())),
            _ => Ok(Validator::Invalid),
        }
    }
}

#[cfg(test)]
mod tests {
    use encode;
    use value::Value;
    use super::*;
    use super::super::Checklist;
    use rand::prelude::*;
    use std::f64;
    use rand::distributions::Uniform;

    fn read_it(raw: &mut &[u8], is_query: bool) -> io::Result<ValidF64> {
        if let MarkerType::Object(len) = read_marker(raw)? {
            let mut validator = ValidF64::new(is_query);
            object_iterate(raw, len, |field, raw| {
                if !validator.update(field, raw)? {
                    Err(Error::new(InvalidData, "Wasn't a valid F64 validator"))
                }
                else {
                    Ok(())
                }
            })?;
            validator.finalize(); // Don't care about if the validator can pass values or not
            Ok(validator)

        }
        else {
            Err(Error::new(InvalidData, "Not an object"))
        }
    }


    fn rand_float<R: Rng>(rng: &mut R) -> f64 {
        rng.gen()
    }

    #[test]
    fn generate() {
        let valid_count = 10;
        let test_count = 100;

        // Variables used in all tests
        let mut rng = rand::thread_rng();
        let mut test1 = Vec::new();
        let mut val = Vec::with_capacity(9);

        // Test passing any f64
        test1.clear();
        encode::write_value(&mut test1, &msgpack!({
            "type": "F64"
        }));
        let validator = read_it(&mut &test1[..], false).unwrap();
        for _ in 0..test_count {
            val.clear();
            encode::write_value(&mut val, &Value::from(rand_float(&mut rng)));
            validator.validate("", &mut &val[..]).unwrap();
        }
        encode::write_value(&mut val, &Value::from(f64::NAN));
        validator.validate("", &mut &val[..]).unwrap();
        encode::write_value(&mut val, &Value::from(f64::INFINITY));
        validator.validate("", &mut &val[..]).unwrap();
        encode::write_value(&mut val, &Value::from(f64::NEG_INFINITY));
        validator.validate("", &mut &val[..]).unwrap();

        // Test floats in a range
        for _ in 0..valid_count {
            test1.clear();
            let val1 = rand_float(&mut rng);
            let val2 = rand_float(&mut rng);
            let (min, max) = if val1 < val2 { (val1, val2) } else { (val2, val1) };
            encode::write_value(&mut test1, &msgpack!({
                "min": min,
                "max": max
            }));
            let validator = read_it(&mut &test1[..], false).expect(&format!("{:X?}",test1));
            for _ in 0..test_count {
                val.clear();
                let test_val = rand_float(&mut rng);
                encode::write_value(&mut val, &Value::from(test_val.clone()));
                assert_eq!(
                    (test_val >= min) && (test_val <= max),
                    validator.validate("", &mut &val[..]).is_ok(),
                    "{:e} was between {:e} and {:e} but failed validation", test_val, min, max);
            }
        }

        // Test -10 to 10 in a range
        let range = Uniform::new(-10i8, 10i8); 
        for _ in 0..valid_count {
            test1.clear();
            let val1 = rng.sample(range) as f64;
            let val2 = rng.sample(range) as f64;
            let (min, max) = if val1 < val2 { (val1, val2) } else { (val2, val1) };
            encode::write_value(&mut test1, &msgpack!({
                "min": min,
                "max": max
            }));
            let validator = read_it(&mut &test1[..], false).expect(&format!("{:X?}",test1));
            for _ in 0..test_count {
                val.clear();
                let test_val = rng.sample(range) as f64;
                encode::write_value(&mut val, &Value::from(test_val.clone()));
                assert_eq!(
                    (test_val >= min) && (test_val <= max),
                    validator.validate("", &mut &val[..]).is_ok(),
                    "{} was between {} and {} but failed validation", test_val, min, max);
            }
            val.clear();
            let test_val = f64::NAN;
            encode::write_value(&mut val, &Value::from(test_val.clone()));
            assert!(validator.validate("", &mut &val[..]).is_err(), "NAN passed a F64 validator with range");
        }

        // Test -10 to 10 with in/nin
        for _ in 0..valid_count {
            let range = Uniform::new(-10i8, 10i8); 
            test1.clear();
            let mut in_vec: Vec<f64> = Vec::with_capacity(valid_count);
            let mut nin_vec: Vec<f64> = Vec::with_capacity(valid_count);
            for _ in 0..valid_count {
                in_vec.push(rng.sample(range) as f64);
                nin_vec.push(rng.sample(range) as f64);
            }
            let in_vec_val: Vec<Value> = in_vec.iter().map(|&x| Value::from(x)).collect();
            let nin_vec_val: Vec<Value> = nin_vec.iter().map(|&x| Value::from(x)).collect();
            encode::write_value(&mut test1, &msgpack!({
                "in": in_vec_val,
                "nin": nin_vec_val,
            }));
            let validator = read_it(&mut &test1[..], false).expect(&format!("{:X?}",test1));
            for _ in 0..test_count {
                val.clear();
                let test_val = rng.sample(range) as f64;
                encode::write_value(&mut val, &Value::from(test_val.clone()));
                assert_eq!(
                    in_vec.contains(&test_val) && !nin_vec.contains(&test_val),
                    validator.validate("", &mut &val[..]).is_ok(),
                    "{:e} was in `in` and not `nin` but failed validation", test_val);
            }
        }

        // Test in with NAN & infinities
        test1.clear();
        encode::write_value(&mut test1, &msgpack!({
            "in": vec![Value::from(f64::NAN), Value::from(f64::INFINITY), Value::from(f64::NEG_INFINITY)]
        }));
        let validator = read_it(&mut &test1[..], false).expect(&format!("{:X?}",test1));
        val.clear();
        encode::write_value(&mut val, &Value::from(f64::NAN));
        assert!(validator.validate("", &mut &val[..]).is_ok(), "NAN was in `in` but failed validation");
        val.clear();
        encode::write_value(&mut val, &Value::from(f64::INFINITY));
        assert!(validator.validate("", &mut &val[..]).is_ok(), "INFINITY was in `in` but failed validation");
        val.clear();
        encode::write_value(&mut val, &Value::from(f64::NEG_INFINITY));
        assert!(validator.validate("", &mut &val[..]).is_ok(), "NEG_INFINITY was in `in` but failed validation");
        val.clear();
        encode::write_value(&mut val, &Value::from(0f64));
        assert!(validator.validate("", &mut &val[..]).is_err(), "0 was not in `in` but passed validation");

        // Test nin with NAN & infinities
        test1.clear();
        encode::write_value(&mut test1, &msgpack!({
            "nin": vec![Value::from(f64::NAN), Value::from(f64::INFINITY), Value::from(f64::NEG_INFINITY)]
        }));
        let validator = read_it(&mut &test1[..], false).expect(&format!("{:X?}",test1));
        val.clear();
        encode::write_value(&mut val, &Value::from(f64::NAN));
        assert!(validator.validate("", &mut &val[..]).is_err(), "NAN was in `nin` but passed validation");
        val.clear();
        encode::write_value(&mut val, &Value::from(f64::INFINITY));
        assert!(validator.validate("", &mut &val[..]).is_err(), "INFINITY was in `nin` but passed validation");
        val.clear();
        encode::write_value(&mut val, &Value::from(f64::NEG_INFINITY));
        assert!(validator.validate("", &mut &val[..]).is_err(), "NEG_INFINITY was in `nin` but passed validation");
        val.clear();
        encode::write_value(&mut val, &Value::from(0f64));
        assert!(validator.validate("", &mut &val[..]).is_ok(), "0 was not in `nin` but failed validation");
    }

    #[test]
    fn intersect() {
        let valid_count = 10;
        let test_count = 1000;

        // Variables used in all tests
        let mut rng = rand::thread_rng();
        let mut test1 = Vec::new();
        let mut val = Vec::with_capacity(9);

        // Test -10 to 10 in a range
        let range = Uniform::new(-10i8, 10i8); 
        for _ in 0..valid_count {
            test1.clear();
            let val1 = rng.sample(range) as f64;
            let val2 = rng.sample(range) as f64;
            let (min, max) = if val1 < val2 { (val1, val2) } else { (val2, val1) };
            encode::write_value(&mut test1, &msgpack!({
                "min": min,
                "max": max
            }));
            let valid1 = read_it(&mut &test1[..], false).expect(&format!("{:X?}",test1));
            test1.clear();
            let val1 = rng.sample(range) as f64;
            let val2 = rng.sample(range) as f64;
            let (min, max) = if val1 < val2 { (val1, val2) } else { (val2, val1) };
            encode::write_value(&mut test1, &msgpack!({
                "min": min,
                "max": max
            }));
            let valid2 = read_it(&mut &test1[..], false).expect(&format!("{:X?}",test1));
            let validi = valid1.intersect(&Validator::F64(valid2.clone()), false).unwrap();
            println!("Validator 1 = {:?}", valid1);
            println!("Validator 2 = {:?}", valid2);
            if let Validator::F64(ref v) = validi {
                println!("Intersecton = {:?}", v);
            }
            else {
                println!("Intersection always fails to validate");
            }
            for _ in 0..test_count {
                val.clear();
                let test_val = rng.sample(range) as f64;
                encode::write_value(&mut val, &Value::from(test_val.clone()));
                let res1 = valid1.validate("", &mut &val[..]);
                let res2 = valid2.validate("", &mut &val[..]);
                let resi = validi.validate("", &mut &val[..], &Vec::new(), 0, &mut Checklist::new());
                if (res1.is_ok() && res2.is_ok()) != resi.is_ok() {
                    println!("Valid 1   Err = {:?}", res1);
                    println!("Valid 2   Err = {:?}", res2);
                    println!("Intersect Err = {:?}", resi);
                }
                assert_eq!(
                    res1.is_ok() && res2.is_ok(),
                    resi.is_ok(),
                    "Min/Max intersection for F64 validators fails with {}", test_val);
            }
        }

        // Test -10 to 10 with in/nin
        test1.clear();
        let mut in_vec: Vec<Value> = Vec::with_capacity(valid_count);
        let mut nin_vec: Vec<Value> = Vec::with_capacity(valid_count);
        for _ in 0..valid_count {
            in_vec.push(Value::from(rng.sample(range) as f64));
            nin_vec.push(Value::from(rng.sample(range) as f64));
        }
        encode::write_value(&mut test1, &msgpack!({
            "in": in_vec,
            "nin": nin_vec,
        }));
        let valid1 = read_it(&mut &test1[..], false).expect(&format!("{:X?}",test1));
        test1.clear();
        let mut in_vec: Vec<Value> = Vec::with_capacity(valid_count);
        let mut nin_vec: Vec<Value> = Vec::with_capacity(valid_count);
        for _ in 0..valid_count {
            in_vec.push(Value::from(rng.sample(range) as f64));
            nin_vec.push(Value::from(rng.sample(range) as f64));
        }
        encode::write_value(&mut test1, &msgpack!({
            "in": in_vec,
            "nin": nin_vec,
        }));
        let valid2 = read_it(&mut &test1[..], false).expect(&format!("{:X?}",test1));
        let validi = valid1.intersect(&Validator::F64(valid2.clone()), false).unwrap();
        for _ in 0..(10*test_count) {
            val.clear();
            let test_val = rng.sample(range) as f64;
            encode::write_value(&mut val, &Value::from(test_val.clone()));
            let res1 = valid1.validate("", &mut &val[..]);
            let res2 = valid2.validate("", &mut &val[..]);
            let resi = validi.validate("", &mut &val[..], &Vec::new(), 0, &mut Checklist::new());
            if (res1.is_ok() && res2.is_ok()) != resi.is_ok() {
                println!("Valid 1   Err = {:?}", res1);
                println!("Valid 2   Err = {:?}", res2);
                println!("Intersect Err = {:?}", resi);
            }
            assert_eq!(
                res1.is_ok() && res2.is_ok(),
                resi.is_ok(),
                "Set intersection for F64 validators fails with {}", test_val);
        }
    }
}
