package zip

find_eocd_signature :: proc(archive: ^ZipArchive) -> (offset: i64, ok: bool) {
	// First try to search a smaller window, if not possible try the
	// largest possible size
	restore_seek_pos := reader_cursor(archive.reader)
	defer {
		archive.reader.offset = restore_seek_pos
	}

	search_ranges := []i64{1024, size_of(_EocdHdr) + size_of(u16le)}
	found := false
	for search_range, idx in search_ranges {
		total_size := reader_size(archive.reader)
		seek_offset := total_size - search_range
		if seek_offset < 0 {
			seek_offset = 0
		}

		reader_seek(archive.reader, seek_offset)
		for {
			possible_magic := reader_peek_value(archive.reader, u32le) or_continue
			if possible_magic == u32le(Magic.EOCD) {
				offset = archive.reader.offset
				return offset, true
			} else {
				reader_skip(archive.reader, 1) or_break
			}
		}
	}

	archive.reader.offset = restore_seek_pos
	return -1, false
}