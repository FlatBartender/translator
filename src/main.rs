use goblin::Object;
use csv;
use clap::{App, Arg};
use std::io::{Read, BufReader, Write, BufWriter};
use std::fs::File;

struct Translation {
    original: String,
    translated: String,
}

fn load_exe(exe_path: &str) -> std::io::Result<Vec<u8>> {
    let mut fd = File::open(exe_path)?;
    let mut buffer = Vec::new();
    fd.read_to_end(&mut buffer)?;

    Ok(buffer)
}

fn load_translations(csv_path: &str) -> std::io::Result<Vec<Translation>> {
    let fd = File::open(csv_path)?;
    let reader = BufReader::new(fd);

    let mut csv_reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_reader(reader);

    let translations = csv_reader.records()
        .enumerate()
        .filter_map(|(i, result)| {
            let record = if result.is_err() {
                println!("An error occurred: {}", result.err().unwrap());
                return None;
            } else {
                result.unwrap()
            };

            if record.len() != 2 {
                println!("Line {} doesn't have 2 columns: {:?}", i, record);
                return None;
            }
            
            let original = if let Some(string) = record.get(0) {
                string.to_string()
            } else {
                println!("Error getting column 0 line {}", i);
                return None;
            };

            let translated = if let Some(string) = record.get(1) {
                string.to_string()
            } else {
                println!("Error getting column 1 line {}", i);
                return None;
            };

            let translation = Translation {
                original,
                translated,
            };

            Some(translation)
        })
        .collect();

    Ok(translations)
}

fn parse_pe_obj(exe_buf: &Vec<u8>) -> goblin::error::Result<goblin::pe::PE> {
    match Object::parse(exe_buf)? {
        Object::PE(pe) => {
            Ok(pe)
        },
        _ => {
            use std::io::ErrorKind;
            println!("Wrong exe file type");
            Err(std::io::Error::new(ErrorKind::InvalidData, "Wrong exe file type")).map_err(goblin::error::Error::IO)
        }
    }
}

fn string_to_utf16_vec(original: &str) -> Vec<u8> {
    let mut utf16le: Vec<u16> = original.encode_utf16().collect();
    utf16le.push(0);

    let mut end = Vec::new();
    utf16le.into_iter()
        .for_each(|v| {
            // Might change with LE/BE
            end.push(v as u8);
            end.push((v >> 8) as u8);
        });

    end
}

fn translate(slice: &mut [u8], translations: &Vec<Translation>, potentially_harmful: bool) {
    for translation in translations.iter() {
        let original = string_to_utf16_vec(&translation.original);
        let translated = string_to_utf16_vec(&translation.translated);

        if original.len() < translated.len() {
            if potentially_harmful {
                println!("WARNING: {} takes fewer bytes than {}. Errors may happen.", translation.original, translation.translated);
            } else {
                println!("WARNING: {} takes fewer bytes than {}. Skipping this translation.", translation.original, translation.translated);
                continue;
            }
        }

        let replaced = replace_slice(slice, &original[..], &translated[..]);

        println!("Replaced {} occurences of {}", replaced, translation.original);
    }
}

fn replace_slice<T>(source: &mut [T], from: &[T], to: &[T]) -> usize
where
    T: Clone + PartialEq + Default,
{
    let mut number_replaced = 0;
    
    let end_offset = std::cmp::max(from.len(), to.len());

    'outer: for i in 0 .. source.len()-end_offset+1 {
        for j in 0 .. from.len() {
            if source[i+j] != from[j] {
                continue 'outer;
            }
        }

        for j in 0 .. from.len() {
            source[i+j] = T::default();
        }

        for j in 0 .. to.len() {
            source[i+j] = to[j].clone();
        }

        number_replaced += 1;
    }

    number_replaced
}

fn write_result(out_path: &str, exe_buf: &Vec<u8>) -> std::io::Result<()> {
    let file = File::create(out_path)?;
    let mut writer = BufWriter::new(file);

    writer.write_all(&exe_buf[..])?;

    Ok(())
}

fn main() {
    let matches = App::new("Translator")
        .version("1.0")
        .author("Flat Bartender <flat.bartender@gmail.com>")
        .about("Finds strings in an exe files and replaces them with a translation")
        .arg(Arg::with_name("EXE_FILE")
            .help("The input executable file to be translated")
            .required(true))
        .arg(Arg::with_name("CSV_FILE")
            .help("The input CSV file containing the translations. First column is original text, second column is translated text.")
            .required(true))
        .arg(Arg::with_name("OUT_FILE")
             .help("The file to write the translated executable to. Leave blank for default (<exe name>.translated)")
             .required(false))
        .arg(Arg::with_name("potentially harmful")
             .help("Sometimes, the original text may take fewer bytes than the translated text. Replacing those can be harmful. Use this to do it anyway.")
             .required(false)
             .short("p")
             .long("potentially-harmful"))
        .get_matches();

    let exe_path = matches.value_of("EXE_FILE").unwrap();
    let csv_path = matches.value_of("CSV_FILE").unwrap();
    let default_out_path = format!("{}.translated", exe_path);
    let out_path = matches.value_of("OUT_FILE").unwrap_or(&default_out_path);

    let mut exe_buf = load_exe(exe_path).unwrap();
    let translations = load_translations(csv_path).unwrap();
    
    let pe_object = parse_pe_obj(&exe_buf).unwrap();

    pe_object.sections.iter().for_each(|section| {
        let ptr = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;

        if section.name().unwrap() == ".rdata" {
            translate(&mut exe_buf[ptr .. ptr + size], &translations, matches.is_present("potentially harmful"));
        }
    });

    write_result(&out_path, &exe_buf).unwrap();
}
