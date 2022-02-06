#[derive(Debug)]
pub enum Compression {
    None,
    #[cfg(feature = "flate2")]
    Zlib,
}

#[derive(Debug)]
pub enum Compress {
    None,
    #[cfg(feature = "flate2")]
    Zlib(flate2::Compress),
}

#[derive(Debug)]
pub enum Decompress {
    None,
    #[cfg(feature = "flate2")]
    Zlib(flate2::Decompress),
}

#[cfg(feature = "flate2")]
impl Compression {
    pub fn from_string(s: &str) -> Self {
        if s == "zlib" || s == "zlib@openssh.com" {
            Compression::Zlib
        } else {
            Compression::None
        }
    }

    pub fn init_compress(&self, comp: &mut Compress) {
        if let Compression::Zlib = *self {
            if let Compress::Zlib(ref mut c) = *comp {
                c.reset()
            } else {
                *comp = Compress::Zlib(flate2::Compress::new(flate2::Compression::fast(), true))
            }
        } else {
            *comp = Compress::None
        }
    }

    pub fn init_decompress(&self, comp: &mut Decompress) {
        if let Compression::Zlib = *self {
            if let Decompress::Zlib(ref mut c) = *comp {
                c.reset(true)
            } else {
                *comp = Decompress::Zlib(flate2::Decompress::new(true))
            }
        } else {
            *comp = Decompress::None
        }
    }
}

#[cfg(not(feature = "flate2"))]
impl Compression {
    pub fn from_string(_: &str) -> Self {
        Compression::None
    }

    pub fn init_compress(&self, _: &mut Compress) {}

    pub fn init_decompress(&self, _: &mut Decompress) {}
}

#[cfg(not(feature = "flate2"))]
impl Compress {
    pub fn compress<'a>(
        &mut self,
        input: &'a [u8],
        _: &'a mut cryptovec::CryptoVec,
    ) -> Result<&'a [u8], Error> {
        Ok(input)
    }
}

#[cfg(not(feature = "flate2"))]
impl Decompress {
    pub fn decompress<'a>(
        &mut self,
        input: &'a [u8],
        _: &'a mut cryptovec::CryptoVec,
    ) -> Result<&'a [u8], Error> {
        Ok(input)
    }
}

#[cfg(feature = "flate2")]
impl Compress {
    pub fn compress<'a>(
        &mut self,
        input: &'a [u8],
        output: &'a mut cryptovec::CryptoVec,
    ) -> Result<&'a [u8], crate::Error> {
        match *self {
            Compress::None => Ok(input),
            Compress::Zlib(ref mut z) => {
                output.clear();
                let n_in = z.total_in() as usize;
                let n_out = z.total_out() as usize;
                output.resize(input.len() + 10);
                let flush = flate2::FlushCompress::Partial;
                loop {
                    let n_in_ = z.total_in() as usize - n_in;
                    let n_out_ = z.total_out() as usize - n_out;
                    let c = z.compress(&input[n_in_..], &mut output[n_out_..], flush)?;
                    match c {
                        flate2::Status::BufError => {
                            output.resize(output.len() * 2);
                        }
                        _ => break,
                    }
                }
                let n_out_ = z.total_out() as usize - n_out;
                Ok(&output[..n_out_])
            }
        }
    }
}

#[cfg(feature = "flate2")]
impl Decompress {
    pub fn decompress<'a>(
        &mut self,
        input: &'a [u8],
        output: &'a mut cryptovec::CryptoVec,
    ) -> Result<&'a [u8], crate::Error> {
        match *self {
            Decompress::None => Ok(input),
            Decompress::Zlib(ref mut z) => {
                output.clear();
                let n_in = z.total_in() as usize;
                let n_out = z.total_out() as usize;
                output.resize(input.len());
                let flush = flate2::FlushDecompress::None;
                loop {
                    let n_in_ = z.total_in() as usize - n_in;
                    let n_out_ = z.total_out() as usize - n_out;
                    let d = z.decompress(&input[n_in_..], &mut output[n_out_..], flush);
                    match d? {
                        flate2::Status::Ok => {
                            output.resize(output.len() * 2);
                        }
                        _ => break,
                    }
                }
                let n_out_ = z.total_out() as usize - n_out;
                Ok(&output[..n_out_])
            }
        }
    }
}
