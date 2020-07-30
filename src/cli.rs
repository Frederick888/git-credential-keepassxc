use anyhow::Error;
use std::str::FromStr;

#[derive(Debug)]
pub struct UnlockOptions {
    pub max_retries: usize,
    pub interval: u64,
}

impl FromStr for UnlockOptions {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Ok(Self {
                max_retries: 0,
                interval: 1000,
            });
        }
        let options: Vec<_> = s.split(',').collect();
        let max_retries = usize::from_str(options[0])?;
        let options = if options.len() == 1 {
            Self {
                max_retries,
                interval: 1000,
            }
        } else {
            let interval = u64::from_str(options[1])?;
            Self {
                max_retries,
                interval,
            }
        };
        Ok(options)
    }
}
