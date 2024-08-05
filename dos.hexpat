import std.io;
import std.mem;

struct RelocationItem {
    u16 offset [[format("format_u16_hex")]];
    u16 segment [[format("format_u16_hex")]];
    u16 target @ parent.codeStart + segment * 16 + offset [[format("format_u16_hex")]];
};

fn format_u16_hex(u16 val) {
    return std::format("0x{:04X}", val);
};

fn format_u8_hex(u8 val) {
    return std::format("0x{:02X}", val);
};

fn computeChecksum(u32 fileSize) {
    u16 checksum = 0;
    for (u32 i = 0, i < fileSize - 1, i += 2) {
        checksum += std::mem::read_unsigned(i, 2);
    }
    
    if (fileSize % 2 == 1) {
        checksum += std::mem::read_unsigned(fileSize - 1, 1);
    }
    
    return checksum;
};

struct DOSHeader {
    char signature[2];
    
    if (signature != "MZ") {
        std::warning("DOS signature not valid.");
        return;
    }
    
    u16 lastPageSize [[format("format_u16_hex")]];
    u16 numPages [[format("format_u16_hex")]];
    
    if (numPages < 1 || numPages == 1 && lastPageSize < 32) {
        std::warning("DOS header reports less than minimum bytes in file.");
        return;
    }
    
    u16 numRelocationItems;
    u16 headerParagraphs [[format("format_u16_hex")]];
    
    if (headerParagraphs < 2) {
        std::warning("DOS header reports less than minimum header paragraphs.");
        return;
    }
    
    u32 codeStart = headerParagraphs * 16;
    u32 fileSize = 256 * (numPages - (lastPageSize == 0 ? 0 : 1)) + lastPageSize;
    u32 codeSize = fileSize - codeStart;
    
    u16 minAlloc [[format("format_u16_hex")]];
    u16 maxAlloc [[format("format_u16_hex")]];
    u16 initialSS [[format("format_u16_hex")]];
    u16 initialSP [[format("format_u16_hex")]];
    
    std::print("Initial top of stack: 0x{:04X}", initialSS * 16 + codeStart + initialSP);
    
    u16 checksum [[format("format_u16_hex")]];
    
    if (computeChecksum(fileSize) != 0xFFFF) {
        std::warning(std::format("DOS checksum failed, should be 0x{:04X}", u16(0xFFFF + checksum - computeChecksum(fileSize))));
    }
    
    u16 initialIP [[format("format_u16_hex")]];
    u16 initialCS [[format("format_u16_hex")]];
    
    u8 entryPoint @ codeStart + 16 * initialCS + initialIP [[format("format_u8_hex")]];
    RelocationItem* relocationTable[numRelocationItems] : u16;
    u16 overlayNum;
};

struct DOSExecutable {
    DOSHeader dosHeader;
    std::mem::Bytes<dosHeader.codeSize> code @ dosHeader.codeStart;
};

DOSExecutable dosExe @ 0 [[inline]];