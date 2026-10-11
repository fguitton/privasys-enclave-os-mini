//! Bounded accepted DATA read batches inside the existing Honest envelope.
//! Scope bytes select addresses, never grant read/publication authority.
#[cfg(feature="sgx")]
use alloc::vec::Vec;
#[cfg(not(feature="sgx"))]
use std::vec::Vec;
use super::{MAX_WORKER_STORAGE_BATCH_RECORDS,MAX_WORKER_STORAGE_BATCH_TABLE_BYTES,MAX_WORKER_STORAGE_BATCH_KEY_BYTES,MAX_HONEST_RPC_PAYLOAD_BYTES,HONEST_REQ_HEADER_SIZE,HONEST_RESP_HEADER_SIZE};
use super::super::framed_payload_len_valid;
const SCOPE_BYTES:usize=core::mem::size_of::<[u8;32]>();
pub const WORKER_GET_BATCH_RESPONSE_HEADER_BYTES:usize=core::mem::size_of::<u16>();
pub const WORKER_GET_BATCH_VALUE_HEADER_BYTES:usize=core::mem::size_of::<u32>();
pub fn worker_get_batch_response_demand(maxima:&[usize])->Option<usize>{
    if maxima.is_empty()||maxima.len()>MAX_WORKER_STORAGE_BATCH_RECORDS{return None;}
    let mut length=WORKER_GET_BATCH_RESPONSE_HEADER_BYTES;
    for maximum in maxima {if *maximum==0 {return None;}u32::try_from(*maximum).ok()?;length=length.checked_add(WORKER_GET_BATCH_VALUE_HEADER_BYTES)?.checked_add(*maximum)?;}
    Some(length)
}
fn request_header(table_bytes:usize)->Option<usize>{SCOPE_BYTES.checked_add(2*core::mem::size_of::<u16>())?.checked_add(table_bytes)}
fn request_record(key_bytes:usize)->Option<usize>{key_bytes.checked_add(core::mem::size_of::<u16>()+core::mem::size_of::<u32>())}
/// Size-only homogeneous window derived from this codec and actual installed
/// request/response capacities. No scope, permission, allocation or IO.
pub fn worker_get_batch_geometry(table:&[u8],key:usize,value:usize,request_maximum:usize,response_maximum:usize)->Option<(usize,usize)>{
    if table.is_empty()||table.len()>MAX_WORKER_STORAGE_BATCH_TABLE_BYTES||key==0||key>MAX_WORKER_STORAGE_BATCH_KEY_BYTES||value==0{return None;}
    u32::try_from(value).ok()?;
    let header=request_header(table.len())?;
    let record=request_record(key)?;
    let request_payload=request_maximum.checked_sub(HONEST_REQ_HEADER_SIZE)?.min(MAX_HONEST_RPC_PAYLOAD_BYTES).checked_sub(1)?;
    let response_payload=response_maximum.checked_sub(HONEST_RESP_HEADER_SIZE)?.min(MAX_HONEST_RPC_PAYLOAD_BYTES);
    let count=MAX_WORKER_STORAGE_BATCH_RECORDS
        .min(request_payload.checked_sub(header)?/record)
        .min(response_payload.checked_sub(WORKER_GET_BATCH_RESPONSE_HEADER_BYTES)?/value.checked_add(WORKER_GET_BATCH_VALUE_HEADER_BYTES)?);
    if count==0{return None;}
    Some((count,header.checked_add(count.checked_mul(record)?)?))
}
pub fn worker_get_batch_encoded_len(scope:[u8;32],table:&[u8],requests:&[(&[u8],usize)],request_maximum:usize,response_maximum:usize)->Option<usize>{
    if scope==[0;32]||table.is_empty()||table.len()>MAX_WORKER_STORAGE_BATCH_TABLE_BYTES||requests.is_empty()||requests.len()>MAX_WORKER_STORAGE_BATCH_RECORDS{return None;}
    let mut length=request_header(table.len())?;
    let mut reply=WORKER_GET_BATCH_RESPONSE_HEADER_BYTES;
    for(key,maximum)in requests{
        if key.is_empty()||key.len()>MAX_WORKER_STORAGE_BATCH_KEY_BYTES||*maximum==0{return None;}
        u32::try_from(*maximum).ok()?;
        length=length.checked_add(request_record(key.len())?)?;
        reply=reply.checked_add(WORKER_GET_BATCH_VALUE_HEADER_BYTES)?.checked_add(*maximum)?;
    }
    // Storage opcode consumes one Honest REQUEST payload byte; response has no opcode.
    if !framed_payload_len_valid(length.checked_add(1)?,HONEST_REQ_HEADER_SIZE,request_maximum)
        ||length.checked_add(1)?>MAX_HONEST_RPC_PAYLOAD_BYTES||reply>MAX_HONEST_RPC_PAYLOAD_BYTES
        ||!framed_payload_len_valid(reply,HONEST_RESP_HEADER_SIZE,response_maximum){return None;}
    Some(length)
}
pub fn encode_worker_get_batch(scope:[u8;32],table:&[u8],requests:&[(&[u8],usize)],request_maximum:usize,response_maximum:usize)->Option<Vec<u8>>{
    let length=worker_get_batch_encoded_len(scope,table,requests,request_maximum,response_maximum)?;
    let mut out=Vec::new();out.try_reserve_exact(length).ok()?;if out.capacity()>length{return None;}
    out.extend_from_slice(&scope);out.extend_from_slice(&u16::try_from(table.len()).ok()?.to_le_bytes());out.extend_from_slice(table);out.extend_from_slice(&u16::try_from(requests.len()).ok()?.to_le_bytes());
    for(key,maximum)in requests{out.extend_from_slice(&u16::try_from(key.len()).ok()?.to_le_bytes());out.extend_from_slice(&u32::try_from(*maximum).ok()?.to_le_bytes());out.extend_from_slice(key);}Some(out)
}
fn take<'a>(input:&mut &'a[u8],count:usize)->Option<&'a[u8]>{let(head,tail)=input.split_at_checked(count)?;*input=tail;Some(head)}
pub fn decode_worker_get_batch(mut bytes:&[u8],request_maximum:usize,response_maximum:usize)->Option<([u8;32],&[u8],Vec<(&[u8],usize)>)>{
    let scope=take(&mut bytes,SCOPE_BYTES)?.try_into().ok()?;
    let table_length=usize::from(u16::from_le_bytes(take(&mut bytes,2)?.try_into().ok()?));
    let table=take(&mut bytes,table_length)?;
    let count=usize::from(u16::from_le_bytes(take(&mut bytes,2)?.try_into().ok()?));
    if count==0||count>MAX_WORKER_STORAGE_BATCH_RECORDS{return None;}
    let mut records=Vec::new();records.try_reserve_exact(count).ok()?;if records.capacity()>count{return None;}
    for _ in 0..count{let length=usize::from(u16::from_le_bytes(take(&mut bytes,2)?.try_into().ok()?));let maximum=usize::try_from(u32::from_le_bytes(take(&mut bytes,4)?.try_into().ok()?)).ok()?;records.push((take(&mut bytes,length)?,maximum));}
    if !bytes.is_empty(){return None;}
    worker_get_batch_encoded_len(scope,table,&records,request_maximum,response_maximum)?;Some((scope,table,records))
}
pub fn encode_worker_get_batch_response(values:&[&[u8]],maxima:&[usize],response_maximum:usize)->Option<Vec<u8>>{
    if values.len()!=maxima.len(){return None;}
    let demand=worker_get_batch_response_demand(maxima)?;
    if demand>MAX_HONEST_RPC_PAYLOAD_BYTES||!framed_payload_len_valid(demand,HONEST_RESP_HEADER_SIZE,response_maximum){return None;}
    let mut length=WORKER_GET_BATCH_RESPONSE_HEADER_BYTES;
    for(value,maximum)in values.iter().zip(maxima){if value.is_empty()||value.len()>*maximum{return None;}length=length.checked_add(WORKER_GET_BATCH_VALUE_HEADER_BYTES)?.checked_add(value.len())?;}
    let mut out=Vec::new();out.try_reserve_exact(length).ok()?;if out.capacity()>length{return None;}
    out.extend_from_slice(&u16::try_from(values.len()).ok()?.to_le_bytes());for value in values{out.extend_from_slice(&u32::try_from(value.len()).ok()?.to_le_bytes());out.extend_from_slice(value);}Some(out)
}
pub fn decode_worker_get_batch_response<'a>(mut bytes:&'a[u8],maxima:&[usize])->Option<Vec<&'a[u8]>>{
    if bytes.len()>MAX_HONEST_RPC_PAYLOAD_BYTES{return None;}
    worker_get_batch_response_demand(maxima)?;
    let count=usize::from(u16::from_le_bytes(take(&mut bytes,2)?.try_into().ok()?));if count!=maxima.len(){return None;}
    let mut values=Vec::new();values.try_reserve_exact(count).ok()?;if values.capacity()>count{return None;}
    for maximum in maxima{let length=usize::try_from(u32::from_le_bytes(take(&mut bytes,4)?.try_into().ok()?)).ok()?;if length==0||length>*maximum{return None;}values.push(take(&mut bytes,length)?);}
    if !bytes.is_empty(){return None;}Some(values)
}
