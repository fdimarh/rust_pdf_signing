use lopdf::{Document, Object};

fn hex_sample(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<String>>().join("")
}

fn inspect_pdf(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n========== Loading {} ==========", path);
    let doc = Document::load(path)?;
    let root = doc.trailer.get(b"Root")?.as_reference()?;
    let root_dict = doc.get_object(root)?.as_dict()?;
    println!("Root object id: {:?}", root);

    // --- AcroForm ---
    if root_dict.has(b"AcroForm") {
        let acro_ref = root_dict.get(b"AcroForm")?.as_reference()?;
        println!("AcroForm object id: {:?}", acro_ref);
        let acro = doc.get_object(acro_ref)?.as_dict()?;
        // Print SigFlags
        if acro.has(b"SigFlags") {
            println!("AcroForm SigFlags: {:?}", acro.get(b"SigFlags")?);
        } else {
            println!("AcroForm SigFlags: MISSING ⚠️");
        }
        if acro.has(b"Fields") {
            let fields = acro.get(b"Fields")?.as_array()?;
            for f in fields {
                match f.as_reference() {
                    Ok(fid) => {
                        println!("Field obj: {:?}", fid);
                        let fdict = doc.get_object(fid)?.as_dict()?;
                        // Check if merged field-widget
                        let is_merged = fdict.has(b"FT") && fdict.has(b"Subtype");
                        println!("  Merged field-widget: {}", is_merged);
                        if fdict.has(b"T") {
                            let t = fdict.get(b"T")?;
                            match t {
                                Object::String(bytes, _) => println!("  /T: {}", String::from_utf8_lossy(bytes)),
                                Object::Name(n) => println!("  /T (name): {}", String::from_utf8_lossy(n)),
                                _ => println!("  /T: (other)")
                            }
                        }
                        if fdict.has(b"V") {
                            let vref = fdict.get(b"V")?.as_reference()?;
                            println!("  V ref: {:?}", vref);
                            let vdict = doc.get_object(vref)?.as_dict()?;
                            println!("  V dict keys:");
                            for (k, v) in vdict.iter() {
                                let key_str = String::from_utf8_lossy(&k);
                                print!("    {}: ", key_str);
                                match v {
                                    Object::String(bytes, _) => {
                                        println!("String(len={}): {}...", bytes.len(), if bytes.len()>16 {hex_sample(&bytes[..16])} else {hex_sample(bytes)})
                                    }
                                    Object::Name(n) => println!("Name({})", String::from_utf8_lossy(n)),
                                    Object::Array(arr) => {
                                        if key_str == "ByteRange" {
                                            let nums: Vec<String> = arr.iter().map(|o| match o { Object::Integer(i) => i.to_string(), Object::Reference(r) => format!("ref({},{})", r.0,r.1), _ => format!("{:?}", o) }).collect();
                                            println!("Array({})", nums.join(", "))
                                        } else {
                                            println!("Array(len={})", arr.len())
                                        }
                                    }
                                    Object::Integer(i) => println!("Integer({})", i),
                                    Object::Dictionary(_) => println!("Dictionary"),
                                    _ => println!("Other({:?})", v),
                                }
                            }
                        }
                        if fdict.has(b"Kids") {
                            let kids = fdict.get(b"Kids")?;
                            println!("  Kids: {:?}", kids);
                        }
                    }
                    Err(e) => println!("Field is not a reference: {:?}", e),
                }
            }
        } else {
            println!("AcroForm has no Fields");
        }
    } else {
        println!("Root has no AcroForm");
    }

    // --- Pages ---
    if root_dict.has(b"Pages") {
        let pages_ref = root_dict.get(b"Pages")?.as_reference()?;
        let pages = doc.get_object(pages_ref)?.as_dict()?;
        if pages.has(b"Kids") {
            let kids = pages.get(b"Kids")?.as_array()?;
            println!("Total top-level page nodes: {}", kids.len());
            for (page_idx, k) in kids.iter().enumerate() {
                if let Ok(page_ref) = k.as_reference() {
                    println!("Page {} (obj {:?}):", page_idx + 1, page_ref);
                    let page = doc.get_object(page_ref)?.as_dict()?;

                    // Print Resources keys
                    if page.has(b"Resources") {
                        let res = page.get(b"Resources")?;
                        match res {
                            Object::Dictionary(d) => {
                                let keys: Vec<String> = d.iter().map(|(k, _)| String::from_utf8_lossy(k).to_string()).collect();
                                println!("  Resources keys: {:?}", keys);
                                // Print Font sub-dict keys
                                if d.has(b"Font") {
                                    if let Ok(Object::Dictionary(fd)) = d.get(b"Font") {
                                        let fkeys: Vec<String> = fd.iter().map(|(k, _)| String::from_utf8_lossy(k).to_string()).collect();
                                        println!("  Fonts: {:?}", fkeys);
                                    }
                                }
                                // Print ColorSpace sub-dict keys
                                if d.has(b"ColorSpace") {
                                    if let Ok(Object::Dictionary(cd)) = d.get(b"ColorSpace") {
                                        let ckeys: Vec<String> = cd.iter().map(|(k, _)| String::from_utf8_lossy(k).to_string()).collect();
                                        println!("  ColorSpaces: {:?}", ckeys);
                                    }
                                }
                                // Print XObject sub-dict keys
                                if d.has(b"XObject") {
                                    if let Ok(Object::Dictionary(xd)) = d.get(b"XObject") {
                                        let xkeys: Vec<String> = xd.iter().map(|(k, _)| String::from_utf8_lossy(k).to_string()).collect();
                                        println!("  XObjects: {:?}", xkeys);
                                    }
                                }
                            }
                            Object::Reference(rref) => println!("  Resources: indirect ref {:?}", rref),
                            _ => println!("  Resources: (other)"),
                        }
                    } else {
                        println!("  No Resources");
                    }

                    // Print Annotations
                    if page.has(b"Annots") {
                        let annots = page.get(b"Annots")?.as_array()?;
                        for a in annots {
                            if let Ok(ann_ref) = a.as_reference() {
                                println!("  Annot: {:?}", ann_ref);
                                let annot = doc.get_object(ann_ref)?.as_dict()?;
                                if annot.has(b"Subtype") {
                                    println!("    Subtype: {}", String::from_utf8_lossy(annot.get(b"Subtype")?.as_name()?));
                                }
                                if annot.has(b"P") {
                                    println!("    P: {:?}", annot.get(b"P")?);
                                }
                                if annot.has(b"AP") {
                                    let ap = annot.get(b"AP")?;
                                    println!("    AP: {:?}", ap);
                                    if let Ok(apdict) = ap.as_dict() {
                                        if apdict.has(b"N") {
                                            println!("    AP.N: {:?}", apdict.get(b"N")?);
                                        }
                                    }
                                }
                                if annot.has(b"Rect") {
                                    println!("    Rect: {:?}", annot.get(b"Rect")?);
                                }
                            }
                        }
                    } else {
                        println!("  No Annots");
                    }
                }
            }
        }
    }

    // --- Scan all objects for Widget annotations ---
    println!("Scanning all objects for Annot/Widget types...");
    for (id, object) in doc.objects.iter() {
        if let Ok(dict) = object.as_dict() {
            if dict.has(b"Type") {
                if let Ok(name) = dict.get(b"Type").and_then(|t| t.as_name()) {
                    if name == b"Annot" {
                        println!("Found Annot object: {:?}", id);
                        if dict.has(b"Subtype") {
                            if let Ok(s) = dict.get(b"Subtype").and_then(|t| t.as_name()) {
                                println!("  Subtype: {}", String::from_utf8_lossy(s));
                            }
                        }
                        if dict.has(b"P") {
                            println!("  P: {:?}", dict.get(b"P")?);
                        }
                        if dict.has(b"Parent") {
                            println!("  Parent: {:?}", dict.get(b"Parent")?);
                        }
                        if dict.has(b"AP") {
                            println!("  AP: {:?}", dict.get(b"AP")?);
                        }
                        if dict.has(b"Rect") {
                            println!("  Rect: {:?}", dict.get(b"Rect")?);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let result_path = "examples/result.pdf";
    let pre_path = "examples/assets/sample-pre-sign.pdf";
    let signed_path = "examples/assets/sample-signed.pdf";

    // Inspect result.pdf (from sign_doc example) first
    if std::path::Path::new(result_path).exists() {
        inspect_pdf(result_path)?;
    }

    // Inspect pre-sign if available
    if std::path::Path::new(pre_path).exists() {
        inspect_pdf(pre_path)?;
    }
    // Always inspect signed
    if std::path::Path::new(signed_path).exists() {
        inspect_pdf(signed_path)?;
    } else {
        println!("Signed PDF not found at {}", signed_path);
    }

    Ok(())
}
