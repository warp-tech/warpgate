// Based on the SSPI client example from MSDN: https://docs.microsoft.com/en-us/windows/win32/secauthn/using-sspi-with-a-windows-sockets-client

// This example works with the server example using SSPI. The client and server examples are designed to work together.
// This example demonstrates initializing an authenticating SSPI session with the NTLM, connecting with a server, establishing
// a secure communication session, receiving and decrypting a message from the server within the secure session.

use std::io;
use std::net::TcpStream;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use sspi::{
    AuthIdentity, BufferType, ClientRequestFlags, CredentialUse, DataRepresentation, Ntlm, SecurityBuffer,
    SecurityBufferRef, SecurityStatus, Sspi, SspiImpl, Username,
};

const IP: &str = "127.0.0.1:8080";

fn main() -> Result<(), io::Error> {
    let mut stream = TcpStream::connect(IP).expect("Failed to connect to the server");

    println!("Connected to the server.");

    let mut ntlm = Ntlm::new();

    let account_name = whoami::username().unwrap();
    let computer_name = whoami::hostname().unwrap();
    let username = Username::new(&account_name, Some(&computer_name)).map_err(io::Error::other)?;

    let identity = AuthIdentity {
        username,
        password: String::from("password").into(),
    };

    do_authentication(&mut ntlm, &identity, &mut stream).expect("Failed to authenticate connection");
    println!("Authenticated!");

    let mut trailer = Vec::new();

    // By agreement, the server encrypted the message and set the size
    // of the trailer block to be just what it needed. decrypt_message
    // needs the size of the trailer block.
    //
    // By agreement, the server placed the trailer at the beginning
    // of the message, and the data comes after the trailer.
    println!("Receiving the trailer...");
    read_message(&mut stream, &mut trailer)?;

    let mut data = Vec::new();
    println!("Receiving the data...");
    read_message(&mut stream, &mut data)?;

    println!("Encrypted message: {data:?}");

    let mut msg_buffer = vec![
        SecurityBufferRef::token_buf(&mut trailer),
        SecurityBufferRef::data_buf(&mut data),
    ];

    let _decryption_flags = ntlm.decrypt_message(&mut msg_buffer)?;

    println!("Decrypting...");
    println!(
        "Decrypted message: [{}]",
        std::str::from_utf8(msg_buffer[1].data()).unwrap()
    );

    println!("Communication successfully finished.");

    Ok(())
}

fn do_authentication(ntlm: &mut Ntlm, identity: &AuthIdentity, mut stream: &mut TcpStream) -> Result<(), io::Error> {
    let mut acq_cred_result = ntlm
        .acquire_credentials_handle()
        .with_credential_use(CredentialUse::Outbound)
        .with_auth_data(identity)
        .execute(ntlm)?;

    let mut output_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];
    let username = whoami::username().unwrap();

    let mut builder = ntlm
        .initialize_security_context()
        .with_credentials_handle(&mut acq_cred_result.credentials_handle)
        .with_context_requirements(ClientRequestFlags::CONFIDENTIALITY | ClientRequestFlags::ALLOCATE_MEMORY)
        .with_target_data_representation(DataRepresentation::Native)
        .with_target_name(username.as_str())
        .with_output(&mut output_buffer);

    let _result = ntlm
        .initialize_security_context_impl(&mut builder)?
        .resolve_to_result()?;

    write_message(&mut stream, &output_buffer[0].buffer)?;

    let mut input_buffer = vec![SecurityBuffer::new(Vec::new(), BufferType::Token)];

    loop {
        output_buffer[0].buffer.clear();

        read_message(&mut stream, &mut input_buffer[0].buffer)?;

        let mut builder = ntlm
            .initialize_security_context()
            .with_credentials_handle(&mut acq_cred_result.credentials_handle)
            .with_context_requirements(ClientRequestFlags::CONFIDENTIALITY | ClientRequestFlags::ALLOCATE_MEMORY)
            .with_target_data_representation(DataRepresentation::Native)
            .with_target_name(username.as_str())
            .with_input(&mut input_buffer)
            .with_output(&mut output_buffer);

        let result = ntlm
            .initialize_security_context_impl(&mut builder)?
            .resolve_to_result()?;

        if [SecurityStatus::CompleteAndContinue, SecurityStatus::CompleteNeeded].contains(&result.status) {
            println!("Completing the token...");
            ntlm.complete_auth_token(&mut output_buffer)?;
        }

        write_message(&mut stream, &output_buffer[0].buffer)?;

        input_buffer[0].buffer.clear();

        if ![SecurityStatus::CompleteAndContinue, SecurityStatus::ContinueNeeded].contains(&result.status) {
            break;
        }
    }

    Ok(())
}

// By agreement, the message length is read from the first 2 bytes of the message in little-endian order.
pub fn read_message<T: io::Read, A: io::Write>(stream: &mut T, output_buffer: &mut A) -> Result<(), io::Error> {
    let msg_len = stream.read_u16::<LittleEndian>()?;

    let mut buff = vec![0u8; msg_len as usize];
    stream.read_exact(&mut buff)?;

    output_buffer.write_all(&buff)?;

    println!("Received the buffer [{} bytes]: {:?}", buff.len(), buff);

    Ok(())
}

// By agreement, the message length is written in the first 2 bytes of the message in little-endian order.
pub fn write_message<T: io::Write>(stream: &mut T, input_buffer: &[u8]) -> Result<(), io::Error> {
    if !input_buffer.is_empty() {
        println!("Sending the buffer [{} bytes]: {:?}", input_buffer.len(), input_buffer);

        stream.write_u16::<LittleEndian>(input_buffer.len() as u16)?;
        stream.write_all(input_buffer)?;
    }

    Ok(())
}

#[test]
fn buffer_read_correctly() {
    let mut msg = vec![0x3, 0x0];
    msg.append(&mut b"abc".to_vec());

    let mut buffer = Vec::new();

    read_message(&mut msg.as_slice(), &mut buffer).unwrap();

    assert_eq!(buffer, b"abc".to_vec());
}

#[test]
fn buffer_written_correctly() {
    let mut msg = vec![9, 8, 7];
    let mut stream = Vec::new();

    write_message(&mut stream, &mut msg).unwrap();

    assert_eq!(stream, vec![3, 0, 9, 8, 7]);
}
