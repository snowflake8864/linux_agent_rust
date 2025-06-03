use std::mem::size_of;
enum NL_POLICY_ATTR{
    NL_POLICY_ATTR_UNSPEC = 0,
    NL_POLICY_ATTR_BIN_MSG,
    NL_POLICY_ATTR_STR_MSG,
    NL_POLICY_ATTR_WAIT_FLAG,
    NL_POLICY_ATTR_DATA_MSG,
    __NL_POLICY_ATTR_MAX,
}

pub struct CKernelMsgSendCmd {
    attrs: Vec<Option<(Vec<u8>, usize)>>,
}

impl CKernelMsgSendCmd {
    pub fn new() -> Self {
        Self {
            attrs: vec![None; NL_POLICY_ATTR::__NL_POLICY_ATTR_MAX as usize],
        }
    }

    pub fn get_attr_msg(
        &self,
        attr_index: NL_POLICY_ATTR,
    ) -> Option<&[u8]> {
        let idx = attr_index as usize;
        if idx >= NL_POLICY_ATTR::NL_POLICY_ATTR_UNSPEC as usize
            && idx < NL_POLICY_ATTR::__NL_POLICY_ATTR_MAX as usize
        {
            self.attrs[idx]
                .as_ref()
                .map(|(data, len)| &data[..*len])
        } else {
            None
        }
    }

    pub fn set_attr_msg(
        &mut self,
        attr_index: NL_POLICY_ATTR,
        msg: &[u8],
    ) -> Result<(), ()> {
        let idx = attr_index as usize;
        if idx >= NL_POLICY_ATTR::NL_POLICY_ATTR_UNSPEC as usize
            && idx < NL_POLICY_ATTR::__NL_POLICY_ATTR_MAX as usize
        {
            self.attrs[idx] = Some((msg.to_vec(), msg.len()));
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn clear(&mut self) {
        self.attrs.clear();
        self.attrs
            .resize(NL_POLICY_ATTR::__NL_POLICY_ATTR_MAX as usize, None);
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct KosecsMsgDataHeader {
    pub data_type: i32,
    pub data_len: i32,
}

#[derive(Debug)]

pub struct KosecsMsgData<'a> {
    pub data_type: i32,
    pub data_len: i32,  // 改这里
    pub payload: &'a [u8],
}
impl<'a> KosecsMsgData<'a> {
    pub fn parse(raw: &'a [u8]) -> Option<Self> {
        if raw.len() < 8 {
            return None;
        }

        let data_type = i32::from_ne_bytes(raw[0..4].try_into().ok()?);
        let data_len = i32::from_ne_bytes(raw[4..8].try_into().ok()?);

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

