use std::mem::size_of;
use logging::{log_info,log_error};


#[derive(Debug)]
pub struct KosecsMsgData<'a> {
    pub data_type: u32,
    pub data_len: u32,  
    pub payload: &'a [u8],
}
impl<'a> KosecsMsgData<'a> {
    pub fn parse(raw: &'a [u8]) -> Option<Self> {
        if raw.len() < 8 {
            return None;
        }

        let data_type = u32::from_ne_bytes(raw[0..4].try_into().ok()?);
        let data_len = u32::from_ne_bytes(raw[4..8].try_into().ok()?);
        let data_len_usize = usize::try_from(data_len).ok()?; // 安全转换
        if raw.len() < 8 + data_len_usize {
            return None;
        }

        let payload = &raw[8..(8 + data_len_usize)];
        Some(KosecsMsgData {
            data_type,
            data_len,
            payload,
        })
    }
}

