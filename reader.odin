package zip

Reader :: struct {
	data: []byte,
	offset: i64,
}

reader_init :: proc(reader: ^Reader, buf: []byte) {
  reader.offset = 0
  reader.data = buf
}

reader_size :: proc(reader: ^Reader) -> i64 {
  return i64(len(reader.data))
}

reader_available :: proc(reader: ^Reader) -> i64 {
  return i64(len(reader.data)) - reader.offset
}

reader_seek :: proc(reader: ^Reader, offset: i64) -> (pos: i64, err: Error) {
  if offset < 0 {
    return -1, .Invalid_Argument
  }

  if offset > i64(len(reader.data) - 1) {
    return -1, .Invalid_Offset
  } 
  // Always seek from start of buffer as relative position
  reader.offset = offset
  return i64(reader.offset), .None
}

reader_read_value :: proc(reader: ^Reader, $T: typeid) -> (value: T, err: Error) {
  remaining := reader_available(reader)
  if remaining < size_of(T) {
    err = .Short_Read
    return
  }
  ptr := raw_data(reader.data[reader.offset:])
  value = (^T)(ptr)^
  reader.offset += size_of(T)
  return
}

reader_peek_value :: proc(reader: ^Reader, $T: typeid) -> (value: T, err: Error) {
  remaining := reader_available(reader)
  if remaining < size_of(T) {
    err = .Short_Read
    return
  }
  ptr := raw_data(reader.data[reader.offset:])
  value = (^T)(ptr)^
  return
}

reader_reset_pos :: proc(reader: ^Reader) {
  reader.offset = 0
}

reader_cursor :: proc(reader: ^Reader) -> i64 {
  return reader.offset
}

// Note: Does not clone the slice
reader_read_array :: proc(reader: ^Reader, $T: typeid, count: i64) -> (value: []T, err: Error) {
  remaining := reader_available(reader)
  if remaining < size_of(T) * count {
    return value, .Short_Read
  }

  ptr := raw_data(reader.data[reader.offset:])
  value = ([^]T)(ptr)[:count]
  reader.offset += size_of(T) * count
  return
}

reader_read_string :: proc(reader: ^Reader, count: i64) -> (value: string, err: Error) {
  buf, arr_err := reader_read_array(reader, byte, count)
  return string(buf), arr_err
}

reader_skip :: proc(reader: ^Reader, count_in_bytes: i64) -> (err: Error) {
  if count_in_bytes < 0 {
    return .None
  }
  if reader_available(reader) < count_in_bytes {
    return .Short_Read
  }

  reader.offset += count_in_bytes
  return .None
}

reader_unread :: proc(reader: ^Reader, count_in_bytes: i64) -> (err: Error) {
  reader.offset -= count_in_bytes
  reader.offset = min(reader.offset, 0)
  return .None
}
