use crate::error::{Result, TrojanError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Connect = 0x01,
    UdpAssociate = 0x03,
}

impl Command {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Command::Connect),
            0x03 => Ok(Command::UdpAssociate),
            _ => Err(TrojanError::InvalidCommand(value)),
        }
    }

    #[allow(dead_code)]
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_from_u8() {
        assert_eq!(Command::from_u8(0x01).unwrap(), Command::Connect);
        assert_eq!(Command::from_u8(0x03).unwrap(), Command::UdpAssociate);
        assert!(Command::from_u8(0x02).is_err());
    }

    #[test]
    fn test_command_as_u8() {
        assert_eq!(Command::Connect.as_u8(), 0x01);
        assert_eq!(Command::UdpAssociate.as_u8(), 0x03);
    }
}
