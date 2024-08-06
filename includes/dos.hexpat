#pragma once
#pragma endian little

import std.io;
import std.mem;

fn format_u16_hex(u16 val) {
    return std::format("0x{:04X}", val);
};

fn format_u8_hex(u8 val) {
    return std::format("0x{:02X}", val);
};
    
namespace dos {
    struct RelocationItem {
        u16 offset [[format("format_u16_hex")]];
        u16 segment [[format("format_u16_hex")]];
        u16 target @ parent.code_start + segment * 16 + offset [[format("format_u16_hex")]];
    };
    
    fn compute_checksum(u32 fileSize) {
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
        
        u16 last_page_size [[format("format_u16_hex")]];
        u16 page_count [[format("format_u16_hex")]];
        
        u32 file_size = 256 * (page_count - (last_page_size == 0 ? 0 : 1)) + last_page_size;
        
        if (file_size < 32) {
            std::warning("DOS header reports less than minimum file size.");
            return;
        }
        
        u16 relocation_item_count;
        u16 header_paragraph_count [[format("format_u16_hex")]];
        
        if (header_paragraph_count < 2) {
            std::warning("DOS header reports less than minimum header paragraphs.");
            return;
        }
        
        u32 code_start = header_paragraph_count * 16;
        u32 code_size = file_size - code_start;
        
        u16 min_alloc [[format("format_u16_hex")]];
        u16 max_alloc [[format("format_u16_hex")]];
        u16 initial_SS [[format("format_u16_hex")]];
        u16 initial_SP [[format("format_u16_hex")]];
        
        std::print("Initial top of stack: 0x{:04X}", initial_SS * 16 + code_start + initial_SP);
        
        u16 checksum [[format("format_u16_hex")]];
        
        if (dos::compute_checksum(file_size) != 0xFFFF) {
            std::warning(std::format("DOS checksum failed, should be 0x{:04X}", u16(0xFFFF + checksum - compute_checksum(file_size))));
        }
        
        u16 initial_IP [[format("format_u16_hex")]];
        u16 initial_CS [[format("format_u16_hex")]];
        
        u8 entry_point @ code_start + 16 * initial_CS + initial_IP [[format("format_u8_hex")]];
        RelocationItem* relocation_table[relocation_item_count] : u16;
        u16 overlay_num;
    };
    
    struct DOSExecutable {
        DOSHeader dos_header;
        std::mem::Bytes<dos_header.code_size> code @ dos_header.code_start;
    };
}