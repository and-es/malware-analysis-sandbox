use std::fmt;
use std::num::NonZeroU8;
use std::{collections::HashMap, str::FromStr};

use anyhow::{Context, Error, Result};
use chrono::{DateTime, FixedOffset};
use roxmltree::Document;
use serde::{Deserialize, Serialize};

#[derive(PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct SysmonEventId(NonZeroU8);

impl SysmonEventId {
    pub const PROCESS_CREATE: Self = Self::new_unchecked(1);
    pub const FILE_CREATE_TIME: Self = Self::new_unchecked(2);
    pub const NETWORK_CONNECT: Self = Self::new_unchecked(3);
    pub const PROCESS_TERMINATE: Self = Self::new_unchecked(5);
    pub const DRIVER_LOAD: Self = Self::new_unchecked(6);
    pub const IMAGE_LOAD: Self = Self::new_unchecked(7);
    pub const CREATE_REMOTE_THREAD: Self = Self::new_unchecked(8);
    pub const RAW_ACCESS_READ: Self = Self::new_unchecked(9);
    pub const PROCESS_ACCESS: Self = Self::new_unchecked(10);
    pub const FILE_CREATE: Self = Self::new_unchecked(11);
    pub const REGISTRY_EVENT_ADD_DELETE: Self = Self::new_unchecked(12);
    pub const REGISTRY_EVENT_SET: Self = Self::new_unchecked(13);
    pub const REGISTRY_EVENT_RENAME: Self = Self::new_unchecked(14);
    pub const FILE_CREATE_STREAM_HASH: Self = Self::new_unchecked(15);
    pub const PIPE_EVENT_CREATE: Self = Self::new_unchecked(17);
    pub const PIPE_EVENT_CONNECT: Self = Self::new_unchecked(18);
    pub const WMI_EVENT_FILTER: Self = Self::new_unchecked(19);
    pub const WMI_EVENT_CONSUMER: Self = Self::new_unchecked(20);
    pub const WMI_EVENT_CONSUMER_FILTER: Self = Self::new_unchecked(21);
    pub const DNS_QUERY: Self = Self::new_unchecked(22);
    pub const FILE_DELETE: Self = Self::new_unchecked(23);
    pub const CLIPBOARD_CHANGE: Self = Self::new_unchecked(24);
    pub const PROCESS_TAMPERING: Self = Self::new_unchecked(25);
    pub const FILE_DELETE_DETECTED: Self = Self::new_unchecked(26);

    const fn new_unchecked(n: u8) -> Self {
        Self(unsafe { NonZeroU8::new_unchecked(n) })
    }
}

impl fmt::Debug for SysmonEventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let event_name = match self {
            &Self::PROCESS_CREATE => "Process Create",
            &Self::FILE_CREATE_TIME => "File creation time changed",
            &Self::NETWORK_CONNECT => "Network connection detected",
            &Self::PROCESS_TERMINATE => "Process terminated",
            &Self::DRIVER_LOAD => "Driver loaded",
            &Self::IMAGE_LOAD => "Image loaded",
            &Self::CREATE_REMOTE_THREAD => "CreateRemoteThread detected",
            &Self::RAW_ACCESS_READ => "RawAccessRead detected",
            &Self::PROCESS_ACCESS => "Process accessed",
            &Self::FILE_CREATE => "File created",
            &Self::REGISTRY_EVENT_ADD_DELETE => "Registry object added or deleted",
            &Self::REGISTRY_EVENT_SET => "Registry value set",
            &Self::REGISTRY_EVENT_RENAME => "Registry object renamed",
            &Self::FILE_CREATE_STREAM_HASH => "File stream created",
            &Self::PIPE_EVENT_CREATE => "Pipe Created",
            &Self::PIPE_EVENT_CONNECT => "Pipe Connected",
            &Self::WMI_EVENT_FILTER => "WmiEventFilter activity detected",
            &Self::WMI_EVENT_CONSUMER => "WmiEventConsumer activity detected",
            &Self::WMI_EVENT_CONSUMER_FILTER => "WmiEventConsumerToFilter activity detected",
            &Self::DNS_QUERY => "Dns query",
            &Self::FILE_DELETE => "File Delete archived",
            &Self::CLIPBOARD_CHANGE => "Clipboard changed",
            &Self::PROCESS_TAMPERING => "Process Tampering",
            &Self::FILE_DELETE_DETECTED => "File Delete logged",
            _ => "Unknown event",
        };

        write!(f, "{} {}", u8::from(self.0), event_name)
    }
}

impl FromStr for SysmonEventId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        NonZeroU8::new(s.parse::<u8>()?)
            .map(SysmonEventId)
            .context("Invalid EventID")
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SysmonEvent {
    pub event_id: SysmonEventId,
    pub time_created: DateTime<FixedOffset>,
    pub event_data: HashMap<String, String>,
}

impl SysmonEvent {
    pub fn from_xml(xml: &str) -> Result<Self> {
        let mut event_id_opt = None;
        let mut time_created_opt = None;
        let mut event_data = HashMap::new();

        let event = Document::parse(xml)?;
        let system_xml = event
            .root_element()
            .children()
            .filter(|n| n.tag_name().name() == "System")
            .nth(0)
            .context("No System node")?;
        let event_data_xml = event
            .root_element()
            .children()
            .filter(|n| n.tag_name().name() == "EventData")
            .nth(0)
            .context("No EventData node")?;

        for node in system_xml.children() {
            match node.tag_name().name() {
                "EventID" => {
                    event_id_opt = node
                        .text()
                        .context("EventID is empty")?
                        .parse::<SysmonEventId>()
                        .ok()
                }
                "TimeCreated" => {
                    time_created_opt = DateTime::parse_from_rfc3339(
                        node.attribute("SystemTime")
                            .context("TimeCreated has no SystemTime attribute")?,
                    )
                    .ok()
                }
                _ => (),
            }
        }

        let event_id = event_id_opt.context("No EventID")?;
        let time_created = time_created_opt.context("No TimeCreated")?;

        for node in event_data_xml.children() {
            if node.tag_name().name() == "Data" {
                event_data.insert(
                    node.attribute("Name")
                        .context("EventData/Data has no Name attribute")?
                        .to_string(),
                    node.text()
                        .context("EventData/Data has no text")?
                        .to_string(),
                );
            }
        }

        Ok(SysmonEvent {
            event_id,
            time_created,
            event_data,
        })
    }
}
