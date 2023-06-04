#include <error.hpp>

namespace bighorn {

const char *MessageErrorCategory::name() const noexcept {
    return "message_error";
}

std::string MessageErrorCategory::message(int ev) const {
    switch (static_cast<MessageError>(ev)) {
        case MessageError::ReadError:
            return "could not read from stream";
        case MessageError::Eof:
            return "end of file";
        case MessageError::InvalidLabelChar:
            return "invalid label character";
        case MessageError::LabelTooLong:
            return "label longer than 63 octets";
        case MessageError::NameTooLong:
            return "name longer than 255 octets";
        case MessageError::JumpLimit:
            return "too many pointer jumps";
        default:
            return "unknown message error";
    }
}

std::error_code make_error_code(MessageError e) {
    return {static_cast<int>(e), msgErrCategory};
}

std::error_code make_error_code(bighorn::ResolutionError e) {
    return {static_cast<int>(e), resolutionErrCategory};
}

const char *ResolutionErrorCategory::name() const noexcept {
    return "resolution_error";
}

std::string ResolutionErrorCategory::message(int ev) const {
    switch (static_cast<ResolutionError>(ev)) {
        case ResolutionError::InvalidResponse:
            return "received invalid response";
        case ResolutionError::RecursionLimit:
            return "hit recusion limit";
        case ResolutionError::RemoteFailure:
            return "remote server sent failure";
        case ResolutionError::RemoteRefused:
            return "remote server refused request";
        case ResolutionError::Timeout:
            return "remote server timed out";
        default:
            return "unknown resolution error";
    }
}

}  // namespace bighorn