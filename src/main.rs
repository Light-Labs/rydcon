use std::error::Error;
use std::io::{self, BufRead, Read, StdoutLock, Write};
use std::str::FromStr;
use std::string::ToString;
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;
use std::{error, fmt, process, thread};

use clap::{crate_version, Parser};
use serial::{SerialPort, SystemPort};
use strum::IntoEnumIterator;
use strum_macros::{Display, EnumIter, EnumString, FromRepr};

const VERSION: &'static str = crate_version!();

/// The max length of a COMMAND_INFO response assuming each version character is escaped (12 + 3
/// escape characters).
const MAX_COMMAND_INFO_RESPONSE_BYTES: usize = 15;

/// CLI arguments specification used by clap
#[derive(Parser, Debug)]
#[command(name = "rydcon")]
#[command(version = VERSION)]
#[command(about = "A CLI for Ryder devices")]
struct Args {
    port: String,
}

/// A command that can be sent to a Ryder device.
#[derive(Clone, Copy, Display, EnumString, EnumIter)]
#[repr(u8)]
enum Command {
    #[strum(serialize = "COMMAND_WAKE")]
    Wake = 1,

    #[strum(serialize = "COMMAND_INFO")]
    Info = 2,

    #[strum(serialize = "COMMAND_UNLOCK")]
    Unlock = 3,

    #[strum(serialize = "COMMAND_SETUP")]
    Setup = 10,

    #[strum(serialize = "COMMAND_RESTORE_FROM_SEED")]
    RestoreFromSeed = 11,

    #[strum(serialize = "COMMAND_RESTORE_FROM_MNEMONIC")]
    RestoreFromMnemonic = 12,

    #[strum(serialize = "COMMAND_ERASE")]
    Erase = 13,

    #[strum(serialize = "COMMAND_STACKS_APP_SIGN_IN_REQUEST_LEGACY")]
    StacksAppSignInRequestLegacy = 20,

    #[strum(serialize = "COMMAND_EXPORT_DERIVED_PUBLIC_KEY")]
    ExportDerivedPublicKey = 40,

    #[strum(serialize = "COMMAND_REQUEST_TRANSACTION_SIGN")]
    RequestTransactionSign = 50,

    #[strum(serialize = "COMMAND_REQUEST_STRUCTURED_MESSAGE_SIGN")]
    RequestStructuredMessageSign = 51,

    #[strum(serialize = "COMMAND_REQUEST_IDENTITY_MESSAGE_SIGN")]
    RequestIdentityMessageSign = 60,

    #[strum(serialize = "COMMAND_CANCEL")]
    Cancel = 100,

    #[strum(serialize = "COMMAND_DEBUG")]
    Debug = 255,
}

impl PartialEq<u8> for Command {
    fn eq(&self, other: &u8) -> bool {
        *self as u8 == *other
    }
}

impl PartialEq<Command> for u8 {
    fn eq(&self, other: &Command) -> bool {
        other == self
    }
}

/// A response code that can be received from a Ryder device.
#[derive(Clone, Copy, Display, EnumString, FromRepr)]
#[repr(u8)]
enum Response {
    // Success responses
    #[strum(serialize = "RESPONSE_OK")]
    Ok = 1,

    #[strum(serialize = "RESPONSE_SEND_INPUT")]
    SendInput = 2,

    #[strum(serialize = "RESPONSE_REJECTED")]
    Rejected = 3,

    /// Arbitrary data follows, terminated by `OutputEnd`.
    #[strum(serialize = "RESPONSE_OUTPUT")]
    Output = 4,

    /// Signals the end of data began by `Output`.
    #[strum(serialize = "RESPONSE_OUTPUT_END")]
    OutputEnd = 5,

    /// Removes any special meaning from the following byte.
    #[strum(serialize = "RESPONSE_ESC_SEQUENCE")]
    EscSequence = 6,

    #[strum(serialize = "RESPONSE_WAIT_USER_CONFIRM")]
    WaitUserConfirm = 10,

    #[strum(serialize = "RESPONSE_LOCKED")]
    Locked = 11,

    // Error responses
    #[strum(serialize = "RESPONSE_ERROR_UNKNOWN_COMMAND")]
    ErrorUnknownCommand = 255,

    #[strum(serialize = "RESPONSE_ERROR_NOT_INITIALISED")]
    ErrorNotInitialised = 254,

    #[strum(serialize = "RESPONSE_ERROR_MEMORY_ERROR")]
    ErrorMemoryError = 253,

    #[strum(serialize = "RESPONSE_ERROR_APP_DOMAIN_TOO_LONG")]
    ErrorAppDomainTooLong = 252,

    #[strum(serialize = "RESPONSE_ERROR_APP_DOMAIN_INVALID")]
    ErrorAppDomainInvalid = 251,

    #[strum(serialize = "RESPONSE_ERROR_MNEMONIC_TOO_LONG")]
    ErrorMnemonicTooLong = 250,

    #[strum(serialize = "RESPONSE_ERROR_MNEMONIC_INVALID")]
    ErrorMnemonicInvalid = 249,

    #[strum(serialize = "RESPONSE_ERROR_GENERATE_MNEMONIC")]
    ErrorGenerateMnemonic = 248,

    #[strum(serialize = "RESPONSE_ERROR_INPUT_TIMEOUT")]
    ErrorInputTimeout = 247,

    #[strum(serialize = "RESPONSE_ERROR_NOT_IMPLEMENTED")]
    ErrorNotImplemented = 246,

    #[strum(serialize = "RESPONSE_ERROR_INPUT_TOO_LONG")]
    ErrorInputTooLong = 245,

    #[strum(serialize = "RESPONSE_ERROR_INPUT_MALFORMED")]
    ErrorInputMalformed = 244,

    #[strum(serialize = "RESPONSE_ERROR_DEPRECATED")]
    ErrorDeprecated = 243,
}

impl PartialEq<u8> for Response {
    fn eq(&self, other: &u8) -> bool {
        *self as u8 == *other
    }
}

impl PartialEq<Response> for u8 {
    fn eq(&self, other: &Response) -> bool {
        other == self
    }
}

/// Info about a Ryder device.
struct RyderInfo {
    /// The firmware version running on the device.
    firmware_version: String,
    #[allow(dead_code)]
    /// Whether the device is initialized.
    initialized: bool,
}

/// User input to be sent to the Ryder device.
struct Input(Vec<u8>);

impl FromStr for Input {
    type Err = InvalidInputError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut s = s.to_string();
        // Replace command names with their byte values
        for command in Command::iter() {
            let command_name = command.to_string();
            // Don't waste time checking commands that are longer than the input
            if s.len() >= command_name.len() {
                let value_str = format!("{:02x}", command as u8);
                s = s.replace(&command_name, &value_str);
            }
        }

        // Remove all spaces
        let chars = s.trim().replace(' ', "").chars().collect::<Vec<_>>();
        let mut data = Vec::new();

        // Iterate over pairs of characters and parse them as hexadecimal bytes
        for pair in chars.chunks(2) {
            if pair.len() != 2 {
                return Err(InvalidInputError);
            }

            let byte = u8::from_str_radix(&format!("{}{}", pair[0], pair[1]), 16)
                .map_err(|_| InvalidInputError)?;
            data.push(byte);
        }

        if data.is_empty() {
            Err(InvalidInputError)
        } else {
            Ok(Self(data))
        }
    }
}

#[derive(Debug)]
struct InvalidInputError;

impl fmt::Display for InvalidInputError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Invalid input")
    }
}

impl error::Error for InvalidInputError {}

/// Output from the Ryder device parsed using `parse_output`.
#[derive(Debug, PartialEq)]
enum ParsedResponse {
    /// A single-byte response.
    Single(u8),
    /// A multi-byte response.
    Multiple(Vec<u8>),
}

/// Parses the output from the serial port, applying escape sequences and other special characters.
/// Returns the parsed response(s), as well as `true` if the result is complete or `false` if more
/// data is expected.
fn parse_output(data: &[u8]) -> (Vec<ParsedResponse>, bool) {
    if data.is_empty() {
        return (Vec::new(), true);
    }

    let mut result = Vec::new();
    let mut output_ended = true;

    let mut i = 0;
    // Read all responses in the data
    while i < data.len() {
        let current = data[i];
        if current == Response::Output {
            // Multi-byte responses are signaled by RESPONSE_OUTPUT
            let mut vec = Vec::new();
            // Skip the RESPONSE_OUTPUT
            i += 1;

            // The data is now considered incomplete until RESPONSE_OUTPUT_END is reached
            output_ended = false;
            while i < data.len() {
                if data[i] == Response::EscSequence {
                    // If an escape sequence is found, simply append the escaped data (if available)
                    // and skip the next loop iteration (to avoid reading the escaped data again)
                    if i + 1 < data.len() {
                        vec.push(data[i + 1]);
                        i += 1;
                    }
                } else if data[i] == Response::OutputEnd {
                    // End of data reached
                    output_ended = true;
                    break;
                } else {
                    vec.push(data[i]);
                }

                i += 1;
            }
            result.push(ParsedResponse::Multiple(vec));
        } else {
            // Single-byte responses are the default
            result.push(ParsedResponse::Single(current));
        }

        // Continue looking for more responses in the data
        i += 1;
    }

    (result, output_ended)
}

/// Repeatedly reads from the serial port until the end of the data is reached or `max_bytes` is
/// reached.
fn read_response_to_end(
    port: &mut SystemPort,
    max_bytes: Option<usize>,
) -> Result<Vec<ParsedResponse>, io::Error> {
    // Start the output buffer size at 32 bytes
    let mut buf = vec![0; 32];
    let mut bytes_read = 0;
    let mut response;
    // Read into `buf` until the max number of bytes have been read or the data has ended
    loop {
        bytes_read += port.read(&mut buf[bytes_read..])?;
        // Parse the bytes received so far
        let parsed = parse_output(&buf[0..bytes_read]);
        response = parsed.0;

        let output_end_reached = parsed.1;
        if output_end_reached {
            break;
        }

        if let Some(max) = max_bytes {
            if bytes_read >= max {
                break;
            }
        }

        // If the output buffer is full, increase its size
        if bytes_read == buf.len() {
            buf.extend(&[0; 32]);
        }
    }

    Ok(response)
}
/// Checks whether a response to a COMMAND_INFO command indicates a valid Ryder device or simulator.
/// Returns `Some(..)` with the device info if it is valid or `None` otherwise.
fn parse_info_response(info_response: &ParsedResponse) -> Option<RyderInfo> {
    // The expected parsed response contains 10 bytes, the first 5 of which are 'ryder' in ASCII
    if let ParsedResponse::Multiple(r) = info_response {
        let is_valid = r.len() == 10 && r[0..5] == b"ryder"[..];

        if is_valid {
            let firmware_version = format!("{}.{}.{}", r[5], r[6], r[7]);
            let initialized = r[9] > 0;
            return Some(RyderInfo {
                firmware_version,
                initialized,
            });
        }
    }

    None
}

/// Checks whether the provided serial port is a valid Ryder device or simulator. Returns
/// `Ok(Some(..))` with the device info if it is valid, `Ok(None)` if it is invalid, or `Err` if
/// data could not be written to or read from the port.
fn get_ryder_device_info(port: &mut SystemPort) -> Result<Option<RyderInfo>, io::Error> {
    // Ask the device for info
    port.write(&[Command::Info as u8])?;

    // Read and parse the response
    // NOTE: This doesn't always return false when it could (it returns a timeout error instead in
    //       some cases)
    let response = read_response_to_end(port, Some(MAX_COMMAND_INFO_RESPONSE_BYTES))?;

    if response.is_empty() {
        Ok(None)
    } else {
        Ok(parse_info_response(&response[0]))
    }

}

/// Formats data received from the Ryder device.
fn format_output(output: &ParsedResponse) -> String {
    // Each byte is padded by zeroes to width 2, and bytes are simply concatenated with no
    // separators
    match output {
        ParsedResponse::Single(byte) => format!("{:02x}", byte),
        ParsedResponse::Multiple(bytes) => format!("{:02x?}", bytes)
            .replace(", ", "")
            .replace('[', "")
            .replace(']', ""),
    }
}

/// Formats and prints data received from the Ryder device.
fn print_output(output: &ParsedResponse, stdout: &mut StdoutLock) {
    let mut string = format!("< {}", format_output(output));

    if let ParsedResponse::Single(byte) = output {
        if let Some(response) = Response::from_repr(*byte) {
            string.extend(format!(" ({})", response.to_string()).chars());
        }
    }

    writeln!(stdout, "{}", string).expect("Failed to print to stdout");
}

/// Starts the work thread that handles receives inputs from the main thread, sends them to the
/// Ryder device for processing asynchronously, and displays any responses received.
///
/// `prompt_rx` is used to determine whether the prompt was printed before the output, indicating
/// that the prompt must be reprinted.
fn start_work_thread(
    mut port: SystemPort,
    input_rx: Receiver<Input>,
    ctrlc_rx: Receiver<()>,
    prompt_rx: Receiver<()>,
) {
    // Whether received data can be printed safely without it ending up on the input line
    let mut can_output_safely = false;

    thread::spawn(move || {
        loop {
            // Check for ctrl-c inputs
            if ctrlc_rx.try_recv().is_ok() {
                // Close the serial port and exit
                drop(port);
                process::exit(1);
            }

            // If the next prompt was printed, it is no longer safe to just print output
            if prompt_rx.try_recv().is_ok() {
                can_output_safely = false;
            }

            // Read any responses
            let mut responses = read_response_to_end(&mut port, None);
            if responses.is_ok() {
                let mut stdout = io::stdout().lock();
                // If the next prompt was printed before this output was received, print a
                // newline to avoid the output being printed on the prompt line
                if !can_output_safely {
                    write!(stdout, "\n").expect("Failed to print to stdout");
                }

                // Keep reading and printing responses until a timeout occurs
                while let Ok(rs) = responses {
                    for r in rs {
                        print_output(&r, &mut stdout);
                    }

                    responses = read_response_to_end(&mut port, None);
                }

                if !can_output_safely {
                    write!(stdout, "> ").expect("Failed to print to stdout");
                }

                // Ensure the previous writes are displayed immediately
                stdout.flush().expect("Failed to print to stdout");
            }

            // Check for user inputs and handle them
            if let Ok(input) = input_rx.try_recv() {
                // If the user pressed enter, we are on a new line and can print output safely
                // without causing issues with the prompt
                can_output_safely = true;

                // Send the input
                if let Err(e) = port.write(&input.0) {
                    // Close the serial port and crash if an error occurred
                    drop(port);
                    crash(e.into());
                }
            }
        }
    });
}

fn run(args: Args) -> Result<(), Box<dyn Error>> {
    println!("rydcon version {}", VERSION);

    // Set a ctrl-c handler in order to properly close the serial port before exiting
    let (ctrlc_tx, ctrlc_rx) = mpsc::channel();
    ctrlc::set_handler(move || {
        ctrlc_tx
            .send(())
            .expect("Failed to send signal through channel")
    })?;

    // Open the serial port
    let mut port = serial::open(&args.port)?;
    port.reconfigure(&|settings| {
        settings.set_baud_rate(serial::Baud115200)?;
        Ok(())
    })?;
    port.set_timeout(Duration::from_millis(100))?;

    // Get the device info (if the device is valid)
    let device_info = match get_ryder_device_info(&mut port)? {
        Some(info) => info,
        None => return Err("Serial port is not a valid Ryder device or simulator".into()),
    };

    println!(
        "Connected to Ryder device with firmware version {} at {}\n",
        device_info.firmware_version, args.port,
    );
    println!("Type \"help\" for a list of available commands.");

    // Start background thread to handle inputs and device communication
    let (input_tx, input_rx) = mpsc::channel();
    let (prompt_tx, prompt_rx) = mpsc::channel();
    start_work_thread(port, input_rx, ctrlc_rx, prompt_rx);

    let mut stdin = io::stdin().lock();
    let mut input = String::new();

    // Loop until the user quits with ctrl-c
    loop {
        // Read user input
        print!("> ");
        prompt_tx.send(())?;
        io::stdout().flush()?;

        input.clear();
        stdin.read_line(&mut input)?;

        // Provide a basic help command
        if input.trim() == "help" {
            for command in Command::iter() {
                println!("{} = {:02x}", command, command as u8);
            }
            continue;
        }

        // Parse the input and send it to the work thread
        let input = match Input::from_str(&input) {
            Ok(i) => i,
            Err(e) => {
                println!("{}", e);
                continue;
            }
        };
        input_tx.send(input)?;

        // Wait before showing the next prompt to give a little time for output to be shown cleanly
        // If the output arrives too late anyways, a new prompt line will be printed, which can
        // cause minor issues with the appearance of input entered already (but no issues with
        // functionality)
        thread::sleep(Duration::from_millis(250));
    }
}

/// Prints the error to stderr and exits.
fn crash(error: Box<dyn Error>) -> ! {
    eprintln!("\nAn error occurred: {}", error);
    process::exit(1);
}

fn main() {
    let args = Args::parse();

    match run(args) {
        Ok(_) => {}
        Err(e) => crash(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_output() {
        assert_eq!((vec![], true), parse_output(&[]));
        assert_eq!(
            (vec![ParsedResponse::Single(Response::Ok as _)], true),
            parse_output(&[Response::Ok as _])
        );
        // Unended multi-byte outputs return false
        assert_eq!(
            (vec![ParsedResponse::Multiple(vec![])], false),
            parse_output(&[Response::Output as _])
        );
        assert_eq!(
            (vec![ParsedResponse::Multiple(vec![Response::Ok as _])], false),
            parse_output(&[Response::Output as _, Response::Ok as _])
        );
        assert_eq!(
            (vec![ParsedResponse::Multiple(vec![Response::Ok as _])], true),
            parse_output(&[
                Response::Output as _,
                Response::Ok as _,
                Response::OutputEnd as _
            ])
        );
        // Escaped bytes are included as-is
        assert_eq!(
            (
                vec![ParsedResponse::Multiple(vec![Response::OutputEnd as _])],
                true
            ),
            parse_output(&[
                Response::Output as _,
                Response::EscSequence as _,
                Response::OutputEnd as _,
                Response::OutputEnd as _
            ])
        );
        // Escape sequences are ignored if not followed by a character (and the data is incomplete)
        assert_eq!(
            (vec![ParsedResponse::Multiple(vec![])], false),
            parse_output(&[Response::Output as _, Response::EscSequence as _,])
        );
        // Multiple responses are collected into a list
        assert_eq!(
            (vec![
                ParsedResponse::Single(Response::ErrorDeprecated as _),
                ParsedResponse::Single(Response::Ok as _),
            ], true),
            parse_output(&[Response::ErrorDeprecated as _, Response::Ok as _])
        );
        assert_eq!(
            (vec![
                ParsedResponse::Single(Response::ErrorDeprecated as _),
                ParsedResponse::Multiple(vec![]),
            ], false),
            parse_output(&[Response::ErrorDeprecated as _, Response::Output as _])
        );
        assert_eq!(
            (vec![
                ParsedResponse::Multiple(vec![]),
                ParsedResponse::Single(Response::ErrorDeprecated as _),
            ], true),
            parse_output(&[Response::Output as _, Response::OutputEnd as _, Response::ErrorDeprecated as _])
        );
    }

    #[test]
    fn test_parse_input() {
        assert!(Input::from_str("").is_err());
        assert!(Input::from_str("1").is_err());
        assert!(Input::from_str("zz").is_err());
        assert!(Input::from_str("COMMAND_").is_err());
        assert_eq!(vec![0x01], Input::from_str("01").unwrap().0);
        assert_eq!(vec![0xff], Input::from_str("ff").unwrap().0);
        assert_eq!(vec![0xff, 0x01], Input::from_str("ff01").unwrap().0);
        assert_eq!(vec![0xff, 0x01], Input::from_str("ff 01").unwrap().0);
        assert_eq!(vec![0xff, 0x01], Input::from_str("f f 0 1").unwrap().0);
        assert_eq!(
            vec![Command::Info as u8],
            Input::from_str("COMMAND_INFO").unwrap().0
        );
        assert_eq!(
            vec![Command::Info as u8, 0xff],
            Input::from_str("COMMAND_INFO ff").unwrap().0
        );
    }

    #[test]
    fn test_format_output() {
        assert_eq!(
            "01",
            format_output(&ParsedResponse::Single(Response::Ok as _))
        );
        assert_eq!(
            "01ff",
            format_output(&ParsedResponse::Multiple(vec![
                Response::Ok as _,
                Response::ErrorUnknownCommand as _
            ]))
        );
    }

    #[test]
    fn test_is_valid_ryder_device() {
        assert!(parse_info_response(&ParsedResponse::Single(b'r')).is_none());
        assert!(parse_info_response(&ParsedResponse::Multiple(b"ryder".to_vec())).is_none());

        let mut valid = b"ryder".to_vec();
        valid.extend([0, 0, 5, 0, 1]);
        let info = parse_info_response(&ParsedResponse::Multiple(valid)).unwrap();
        assert_eq!("0.0.5", info.firmware_version);
        assert_eq!(true, info.initialized);
    }
}
