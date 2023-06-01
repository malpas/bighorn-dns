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
        default:
            return "unknown message error";
    }
}

std::error_code make_error_code(MessageError e) {
    return {static_cast<int>(e), msgErrCategory};
}

}  // namespace bighorn