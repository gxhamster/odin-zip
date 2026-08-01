package zip

import "core:io"
import "core:mem"
import "core:bytes"
import "core:os"

Writer :: struct {
  f: ^os.File,
  b: bytes.Buffer,
  s: io.Stream,
  allocator: mem.Allocator,
  is_file: bool,
}

writer_init_with_bytes :: proc(w: ^Writer, b: []byte, allocator: mem.Allocator) {
  byte_buf : bytes.Buffer
  w.is_file = false
  w.b = byte_buf
  w.f = nil
  w.allocator = allocator
  bytes.buffer_init_allocator(&w.b, len(b), len(b), allocator)
  bytes.buffer_init(&w.b, b)
}

writer_init_with_file :: proc(w: ^Writer, file_name: string) -> io.Error {
  file, file_err := os.open(file_name, {.Write})
  if file_err != os.ERROR_NONE {
    return .Unknown
  }

  w.is_file = true
  w.f = file
  w.s = os.to_writer(file)

  return .None
}

writer_write_value :: proc(w: ^Writer, $T: typeid, ptr: rawptr) -> io.Error {
  io.write_ptr(w.s, ptr, size_of(T)) or_return

  return .None
}

writer_seek :: proc(w: ^Writer, offset: i64, whence := io.Seek_From.Start) -> (pos: i64, err: io.Error) {
  if offset < 0 {
    return -1, .Invalid_Offset
  }

  return io.seek(w.s, offset, whence)
}

writer_close :: proc(w: ^Writer) {
  if w.is_file {
    os.close(w.f)
  } else {
    bytes.buffer_destroy(&w.b)
  }
}
