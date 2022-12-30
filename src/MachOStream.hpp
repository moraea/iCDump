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

#ifndef ICDUMP_MACHO_STREAM_H_
#define ICDUMP_MACHO_STREAM_H_
#include <LIEF/BinaryStream/BinaryStream.hpp>

namespace LIEF::MachO {
class Binary;
}

namespace iCDump {
class MachOStream : public LIEF::BinaryStream {
  public:
  MachOStream(const LIEF::MachO::Binary& bin);
  uint64_t size() const override;

  LIEF::result<const void*> read_at(uint64_t offset, uint64_t size) const override;

  inline const LIEF::MachO::Binary& bin() const {
    return *binary_;
  }

  private:
  const LIEF::MachO::Binary* binary_ = nullptr;
};
}
#endif
