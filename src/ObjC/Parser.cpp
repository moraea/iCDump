/* Copyright 2023 R. Thomas
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "iCDump/ObjC/Parser.hpp"
#include "iCDump/ObjC/Metadata.hpp"
#include "iCDump/ObjC/Class.hpp"
#include "iCDump/ObjC/Method.hpp"
#include "iCDump/ObjC/Protocol.hpp"
#include "iCDump/ObjC/Property.hpp"
#include "iCDump/ObjC/IVar.hpp"
#include "MachOStream.hpp"
#include "iCDump/ObjC/Types.hpp"
#include "log.hpp"

#include "LIEF/MachO.hpp"
#include "LIEF/BinaryStream/SpanStream.hpp"

using namespace LIEF::MachO;

namespace iCDump::ObjC {


const Section* get_objc_section(const Binary& bin, const std::string& name) {
  if (const auto* sec = bin.get_section("__DATA", name)) {
    return sec;
  }

  if (const auto* sec = bin.get_section("__DATA_CONST", name)) {
    return sec;
  }

  if (const auto* sec = bin.get_section("__DATA_DIRTY", name)) {
    return sec;
  }
  ICDUMP_DEBUG("Can't find '{}'", name);
  return nullptr;
}

inline const Section* get_objc_classlist(const Binary& bin) {
  return get_objc_section(bin, "__objc_classlist");
}

inline const Section* get_objc_protolist(const Binary& bin) {
  return get_objc_section(bin, "__objc_protolist");
}

Parser::Parser() = default;

Parser::Parser(const Binary* bin) :
  bin_{bin},
  stream_{std::make_unique<MachOStream>(*bin)},
  metadata_{std::make_unique<Metadata>()},
  imagebase_{bin_->imagebase()}
{
}

std::unique_ptr<Metadata> Parser::parse(const Binary& bin) {
  Parser parser(&bin);

  parser
    .process_protocols()
    .process_classes();

  return std::move(parser.metadata_);
}


Protocol* Parser::get_or_create_protocol(uintptr_t offset) {
  if (auto it = protocols_.find(offset); it != std::end(protocols_)) {
    return it->second;
  }


  LIEF::BinaryStream& mstream = stream();
  LIEF::ScopedStream scoped(mstream, offset);

  std::unique_ptr<Protocol> proto = Protocol::create(*this);
  if (!proto) {
    ICDUMP_ERR("Error while parsing protocol at offset 0x{:x}", offset);
    return nullptr;
  }
  auto* raw_ptr = proto.get();
  metadata_->protocol_lookup_[proto->mangled_name()] = proto.get();
  metadata_->protocols_.push_back(std::move(proto));

  return raw_ptr;
}

Parser& Parser::process_protocols() {
  if (const Section* sec = get_objc_protolist(*bin_)) {
    ICDUMP_DEBUG("ObjC Protocol from: {}: 0x{:010x}", sec->name(), sec->virtual_address());
    LIEF::SpanStream protolist(sec->content());
    return process_protocols(*stream_, protolist);
  }
  return *this;
}

Parser& Parser::process_protocols(LIEF::BinaryStream& mstream, LIEF::BinaryStream& protolist) {
  const size_t nb_protos = protolist.size() / sizeof(uintptr_t);
  ICDUMP_DEBUG("Nb protocols: {:d}", nb_protos);
  for (size_t i = 0; i < nb_protos; ++i) {
    uintptr_t location = 0;
    ICDUMP_DEBUG("  __objc_protolist[{}]", i);
    if (auto res = protolist.read<uintptr_t>()) {
      location = decode_ptr(*res);
    } else {
      ICDUMP_WARN("Can't read __objc_protolist[{}]", i);
      break;
    }
    {
      ICDUMP_DEBUG("  __objc_protolist@0x{:010x}", location);
      LIEF::ScopedStream scoped(mstream, location);
      if (std::unique_ptr<Protocol> proto = Protocol::create(*this)) {
        protocols_[location] = proto.get();

        metadata_->protocol_lookup_[proto->mangled_name()] = proto.get();
        metadata_->protocols_.push_back(std::move(proto));
      } else {
        ICDUMP_WARN("Can't read __objc_protolist@0x{:010x}", location);
      }
    }
  }
  return *this;
}

Parser& Parser::process_classes() {
  if (const Section* sec = get_objc_classlist(*bin_)) {
    LIEF::SpanStream classlist(sec->content());
    return process_classes(*stream_, classlist);
  }
  return *this;
}

Parser& Parser::process_classes(LIEF::BinaryStream& mstream, LIEF::BinaryStream& classlist) {
  const size_t nb_classes = classlist.size() / sizeof(uintptr_t);

  ICDUMP_DEBUG("__objc_classlist: #{}", nb_classes);
  for (size_t i = 0; i < nb_classes; ++i) {
    uintptr_t location = 0;
    if (auto res = classlist.read<uintptr_t>()) {
      ICDUMP_DEBUG("  __objc_classlist[{}]: 0x{:010x}", i, location);
      location = decode_ptr(*res);
    } else {
      ICDUMP_WARN("Can't read __objc_classlist[{}]", i);
      break;
    }
    {
      LIEF::ScopedStream scoped(mstream, location);
      ICDUMP_DEBUG("  __objc_classlist@{:010x}", location);
      if (std::unique_ptr<Class> cls = Class::create(*this)) {
        metadata_->classes_lookup_[cls->name()] = cls.get();
        metadata_->classes_.push_back(std::move(cls));
      } else {
        ICDUMP_WARN("Can't read __objc_classlist@0x{:010x}", location);
      }
    }
  }
  return *this;
}

// DYLD_CHAINED_IMPORT
struct dyld_chained_import
{
    uint32_t    lib_ordinal :  8,
                weak_import :  1,
                name_offset : 23;
};

// DYLD_CHAINED_PTR_64
struct dyld_chained_ptr_64_bind
{
    uint64_t    ordinal   : 24,
                addend    :  8,   // 0 thru 255
                reserved  : 19,   // all zeros
                next      : 12,   // 4-byte stride
                bind      :  1;   // == 1
};

struct dyld_chained_ptr_64_rebase
{
    uint64_t    target    : 36,    // 64GB max image size (DYLD_CHAINED_PTR_64 => vmAddr, DYLD_CHAINED_PTR_64_OFFSET => runtimeOffset)
                high8     :  8,    // top 8 bits set to this (DYLD_CHAINED_PTR_64 => after slide added, DYLD_CHAINED_PTR_64_OFFSET => before slide added)
                reserved  :  7,    // all zeros
                next      : 12,    // 4-byte stride
                bind      :  1;    // == 0
};

union dyld_chained_ptr_64 {
  dyld_chained_ptr_64_bind bind;
  dyld_chained_ptr_64_rebase rebase;
  uint64_t combined;
};

// header of the LC_DYLD_CHAINEfD_FIXUPS payload
struct dyld_chained_fixups_header
{
    uint32_t    fixups_version;    // 0
    uint32_t    starts_offset;     // offset of dyld_chained_starts_in_image in chain_data
    uint32_t    imports_offset;    // offset of imports table in chain_data
    uint32_t    symbols_offset;    // offset of symbol strings in chain_data
    uint32_t    imports_count;     // number of imported symbol names
    uint32_t    imports_format;    // DYLD_CHAINED_IMPORT*
    uint32_t    symbols_format;    // 0 => uncompressed, 1 => zlib compressed
};

uintptr_t Parser::decode_ptr(uintptr_t ptr) {
  uintptr_t decoded = ptr & ((1llu << 51) - 1);
  if (imagebase_ > 0 && decoded < imagebase_) {
    decoded += imagebase_;
  }

  dyld_chained_ptr_64 fixup;
  if (bin().has_dyld_chained_fixups()) {
    fixup.combined = ptr;
    if (fixup.combined & (0xFFFF000000000000)) {
      if (fixup.bind.bind == 1) {
        auto linkEditSegment = bin().get_segment("__LINKEDIT");
        size_t linkEditOffset = linkEditSegment->virtual_address() - linkEditSegment->file_offset();

        size_t fixupsHeaderOffset = bin().dyld_chained_fixups()->data_offset() + linkEditOffset;
        auto fixupsHeader = *(stream().peek<dyld_chained_fixups_header>(fixupsHeaderOffset));

        dyld_chained_import fixupImport = *(stream().peek<dyld_chained_import>(fixupsHeaderOffset + fixupsHeader.imports_offset 
                                                                              + (sizeof(dyld_chained_import) * fixup.bind.ordinal)));
        auto bindSymbolName = *(stream().peek_string_at(fixupsHeaderOffset + fixupsHeader.symbols_offset + fixupImport.name_offset));
        auto symbols = bin().symbols();
        const auto it_symbol = std::find_if(std::begin(symbols), std::end(symbols),
                                            [bindSymbolName] (const Symbol& s) {
                                              return (s.name() == bindSymbolName && s.value() > 0);
                                            });
        if (it_symbol == std::end(symbols)) {
          decoded = 0xFFFFFFFFFFFFFFFF;
          ICDUMP_WARN("FIXED PATH: DECODE(0x{:010x}): Returning 0x{:010x} for N_UNDF symbol: {}", ptr, decoded, bindSymbolName);
          return decoded;
        }
        decoded = (*it_symbol).value();
        return decoded;
      } else {
        decoded = imagebase_ + fixup.rebase.target;
        return decoded;
      }
    }
  }

  return decoded;
}

}
