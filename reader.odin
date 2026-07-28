package zip

import "core:io"
import "core:bytes"
import "core:os"

Reader :: struct {
  f: ^os.File,
  b: bytes.Reader,
  r: io.Reader,
  is_file: bool,
}

reader_init_with_file :: proc(reader: ^Reader, file_name: string) -> io.Error {
  file, file_err := os.open(file_name)
  if file_err != os.ERROR_NONE {
    return .Unknown
  }
  reader.f = file
  reader.is_file = true
  reader.r = os.to_reader(reader.f)

  return .None
}

reader_init_with_bytes :: proc(reader: ^Reader, b: []byte) -> io.Error {
  byte_buf : bytes.Reader
  reader.b = byte_buf
  reader.r = bytes.reader_init(&reader.b, b)
  reader.is_file = false

  return .None
}

reader_init :: proc{reader_init_with_bytes, reader_init_with_file}

reader_size :: proc(reader: ^Reader) -> i64 {
  size, err := io.size(reader.r)
  assert(err == io.Error.None)
  return size
}

reader_available :: proc(reader: ^Reader) -> i64 {
  return reader_size(reader) - reader_cursor(reader)
}

reader_seek :: proc(reader: ^Reader, offset: i64) -> (pos: i64, err: io.Error) {
  if offset < 0 {
    return -1, .Invalid_Offset
  }

  return io.seek(reader.r, offset, .Start)
}

reader_read_value :: proc(reader: ^Reader, $T: typeid) -> (value: T, err: io.Error) {
  buf := make([]byte, size_of(T), context.temp_allocator)
  ptr := raw_data(buf)
  io.read_ptr(reader.r, ptr, size_of(T)) or_return
  value = (^T)(ptr)^
  return value, .None
}

reader_peek_value :: proc(reader: ^Reader, $T: typeid) -> (value: T, err: io.Error) {
  restore_seek_pos := reader_cursor(reader)
  if reader_available(reader) < size_of(T) {
    return value, .Negative_Read
  }

  value, err = reader_read_value(reader, T)
  
  // Always restore the previous position of the stream
  reader_seek(reader, restore_seek_pos)

  return value, err
}

reader_reset_pos :: proc(reader: ^Reader) {
  reader_seek(reader, 0)
}

reader_cursor :: proc(reader: ^Reader) -> i64 {
  cur_pos, seek_err := io.seek(reader.r, 0, .Current)
  assert(seek_err == .None)
  return cur_pos
}

reader_read_array :: proc(reader: ^Reader, out: $S/[]$T) -> (err: io.Error) {
  remaining := reader_available(reader)
  if int(remaining) < len(out) {
    return .Negative_Read
  } else {
    io.read_slice(reader.r, out)
    return .None
  }
}

// Will allocate string on the `allocator`
reader_read_string :: proc(reader: ^Reader, count: i64, allocator := context.allocator) -> (value: string, err: io.Error) {
  u8_buf := make([]u8, count, allocator)
  arr_err := reader_read_array(reader, u8_buf)
  if arr_err != .None {
    return value, arr_err
  }
  return string(u8_buf), arr_err
}

reader_skip :: proc(reader: ^Reader, count_in_bytes: i64) -> (err: io.Error) {
  if count_in_bytes < 0 {
    return .None
  }
  if reader_available(reader) < count_in_bytes {
    return .Negative_Read
  }

  cur_pos := reader_cursor(reader)
  cur_pos += count_in_bytes
  skipped_pos := reader_seek(reader, cur_pos) or_return

  return .None
}

reader_read_full :: proc(reader: ^Reader, out: []byte) -> (err: io.Error) {
  if i64(len(out)) < reader_size(reader) {
    return .Short_Buffer
  }
  io.read_full(reader.r, out) or_return

  return .None
}

