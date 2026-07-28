package zip

import "core:bytes"
import "core:compress/zlib"
import "core:mem"
import "core:os"
import "core:strings"
import "core:time"
import "core:time/datetime"
import "core:hash"
import "core:io"


/*
	== TODO ==
	- Register custom methods to read extra fields
	- Register custom compressor/decompressor
	- Most common decryption implemented
	- Multi-part archives
	- io.Stream compatible reader/writer
*/

open_from_path :: proc(
	path: string,
	mode: os.File_Flags,
	allocator := context.allocator,
) -> (
	archive: ZipArchive,
	err: Error,
) {
	if !os.exists(path) {
		return archive, .OS_Error
	}
	file, file_err := os.open(path, mode)
	if file_err != os.ERROR_NONE {
		return archive, .OS_Error
	}

	defer os.close(file)

	archive.file = path
	archive.allocator = allocator

	file_size, file_size_err := os.file_size(file)
	if file_size_err != os.ERROR_NONE {
		return archive, .OS_Error
	}

	if (file_size < size_of(_EocdHdr)) {
		return archive, .Corrupted_Data
	}

	reader: ^Reader = new(Reader, archive.allocator)
	file_data, file_read_err := os.read_entire_file_from_file(file, archive.allocator)
	if file_read_err != nil {
		return archive, .OS_Error
	}
	reader_init(reader, file_data)
	archive.reader = reader

	read_metadata(&archive) or_return

	return archive, ZipError.None
}

// Frees all the resources related to the zip archive
close :: proc(archive: ^ZipArchive) {
	for entry in archive.entries {
		delete(entry.name)
	}

	delete_dynamic_array(archive.entries)
}

// Tries to look for Local Headers in a archive
// with missing central directories. Could be potentially slow
// in large archives
recover :: proc(path: string, allocator := context.allocator) -> (archive: ZipArchive, err: Error) {
	archive.allocator = allocator

	reader: ^Reader = new(Reader, archive.allocator)
	reader_init(reader, path)

	archive.file = path
	archive.reader = reader
	archive.entries = make([dynamic]ZipEntry, archive.allocator)

	// Search for the LFH header
	for {
		if reader_available(reader) < 4 do break

		magic := reader_peek_value(reader, u32le) or_return
		if magic == u32le(Magic.LFH) {
			// Parse the LFH
			hdr_offset := reader_cursor(reader)
			lfh := reader_read_value(reader, _LfHdr) or_return
			file_name := reader_read_string(reader, i64(lfh.file_name_len)) or_break
			entry: ZipEntry
			entry.name = file_name
			entry.compressed_size = i64(lfh.comp_size)
			entry.uncompressed_size = i64(lfh.uncomp_size)
			entry.crc32 = u32(lfh.crc32)
			entry.method = lfh.comp_method
			entry.local_offset = u64(hdr_offset)
			mod_datetime_err: datetime.Error
			entry.modified_datetime = dos_datetime_to_datetime(lfh.mod_date, lfh.mod_time)

			entry.is_directory = strings.ends_with(entry.name, "/") || strings.ends_with(entry.name, "\\")
			entry.is_encrypted = (lfh.flags & 1) != 0
			append(&archive.entries, entry)

			// Skip the file data
			reader_seek(archive.reader, hdr_offset + entry.compressed_size) or_return

		} else {
			reader_skip(reader, 1) or_return
		}
	}

	if len(archive.entries) == 0 {
		return archive, .Corrupted_Data
	}

	return archive, ZipError.None
}


find_eocd_signature :: proc(archive: ^ZipArchive) -> (offset: i64, ok: bool) {
	// First try to search a smaller window, if not possible try the
	// largest possible size
	restore_seek_pos := reader_cursor(archive.reader)
	defer {
		reader_seek(archive.reader, restore_seek_pos)
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
				offset = reader_cursor(archive.reader)
				return offset, true
			} else {
				reader_skip(archive.reader, 1) or_break
			}
		}
	}

	return -1, false
}

// Reads all the directory information inside the zip archive and collect the entries
read_metadata :: proc(archive: ^ZipArchive) -> (err: Error) {
	// Properly find the Zip64 eocd and locator and sets the field in struct
	eocd_offset, ok := find_eocd_signature(archive)
	if !ok {
		return .EOCD_Not_Found
	}

	reader_seek(archive.reader, eocd_offset) or_return
	raw_eocd_hdr := reader_read_value(archive.reader, _EocdHdr) or_return

	// Archives spanning different disks not supported. This aint 1970
	if raw_eocd_hdr.disk_number != raw_eocd_hdr.starting_disk {
		return .Not_Supported
	}

	if (raw_eocd_hdr.comment_length > 0) {
		// TODO: Detect if a proper utf-8 and do the neccesary
		archive.comment = reader_read_string(archive.reader, i64(raw_eocd_hdr.comment_length)) or_return
	}

	if raw_eocd_hdr.offset_to_central_directory_start > max(u32le) {
		return .Invalid_Offset
	}

	num_entries := i64(raw_eocd_hdr.total_central_records)
	archive.entries = make([dynamic]ZipEntry, 0, num_entries, archive.allocator)


	// Check if this zip archive could be a ZIP64 type
	if raw_eocd_hdr.offset_to_central_directory_start == 0xFFFFFFFF || raw_eocd_hdr.total_central_records == 0xFFFF {
		// Find the zip64 locator located before the EOCD
		total_file_size := reader_size(archive.reader)
		locator_position := total_file_size - size_of(_EocdHdr) - size_of(_Zip64_Locator)
		locator_hdr := reader_read_value(archive.reader, _Zip64_Locator) or_return
		if locator_hdr.magic == u32le(Magic.ZIP64_LOCATOR) {
			// Find the zip64 EOCD before the locator
			reader_seek(archive.reader, i64(locator_hdr.offset_eocd)) or_return
			zip64_eocd := reader_read_value(archive.reader, _Zip64EocdHdr) or_return
			if zip64_eocd.magic == u32le(Magic.ZIP64_EOCD) {
				reader_seek(archive.reader, i64(zip64_eocd.offset_cd))
				num_entries = i64(zip64_eocd.entries_total)
			}
		}
	}

	reader_seek(archive.reader, i64(raw_eocd_hdr.offset_to_central_directory_start)) or_return


	for i in 0 ..< num_entries {
		// Read all the central directory entries
		cd_hdr := reader_read_value(archive.reader, _CdHdr) or_break
		if cd_hdr.magic != u32le(Magic.CDH) {
			return ZipError.Corrupted_Data
		}
		file_name_len := i64(cd_hdr.file_name_length)
		// Note: Need to check if odin strings need to be checked for valid utf-8
		file_name := reader_read_string(archive.reader, file_name_len) or_break

		entry: ZipEntry
		entry.name = file_name
		entry.compressed_size = i64(cd_hdr.compressed_size)
		entry.uncompressed_size = i64(cd_hdr.uncompressed_size)
		entry.local_offset = u64(cd_hdr.local_hdr_offset)
		entry.crc32 = u32(cd_hdr.crc)
		entry.method = cd_hdr.compression_method
		entry.modified_datetime = dos_datetime_to_datetime(cd_hdr.last_modified_date, cd_hdr.last_modified_time)

		// note: If these fields are at max good indicator that ZIP64 format is being used
		is_zip64 :=
			cd_hdr.compressed_size == U32_MAX ||
			cd_hdr.uncompressed_size == U32_MAX ||
			cd_hdr.local_hdr_offset == U32_MAX

		if is_zip64 {

			// 4.5 Extensible data fields
			// header1+data1 + header2+data2
			// Each header MUST consist of:
			//      Header ID - 2 bytes
			//      Data Size - 2 bytes

			Extra_Hdr :: struct {
				id:   u16le,
				size: u16le,
			}

			Extra_Zip64 :: struct #packed {
				original_size:     i64,
				compressed_size:   i64,
				hdr_offset:        u64,
				disk_start_number: u32,
			}

			extra_field_len := i64(cd_hdr.extra_field_length)
			extra_field_end_offset := reader_cursor(archive.reader) + extra_field_len

			for reader_available(archive.reader) > size_of(Extra_Hdr) &&
			    reader_cursor(archive.reader) < extra_field_end_offset {
				extra_field_hdr := reader_read_value(archive.reader, Extra_Hdr) or_break

				switch extra_field_hdr.id {
				case 0x0001:
					// Zip64 4.5.3
					{
						zip64_extra := reader_read_value(archive.reader, Extra_Zip64) or_break
						if cd_hdr.compressed_size == U32_MAX {
							entry.compressed_size = zip64_extra.compressed_size
						}
						if cd_hdr.uncompressed_size == U32_MAX {
							entry.uncompressed_size = zip64_extra.original_size
						}
						if cd_hdr.local_hdr_offset == U32_MAX {
							entry.local_offset = zip64_extra.hdr_offset
						}
					}
				case 0x000a:
					// NTFS 4.5.5
					{
						NTFS_TAG1 :: 0x0001
						NTFS_TAG1_SIZE :: 24
						Extra_NTFS_Tag1 :: struct #packed {
							tag:   u16le,
							size:  u16le,
							mtime: u64le,
							atime: u64le,
							ctime: u64le,
						}
						// skip the reserved
						reader_skip(archive.reader, 4)
						ntfs_extra := reader_read_value(archive.reader, Extra_NTFS_Tag1) or_break
						if ntfs_extra.tag == NTFS_TAG1 && ntfs_extra.size == NTFS_TAG1_SIZE {
							WINDOWS_TICKS_PER_SEC :: 1e7
							secs := i64(ntfs_extra.mtime) / WINDOWS_TICKS_PER_SEC
							nsecs := (1e9 / WINDOWS_TICKS_PER_SEC) * (i64(ntfs_extra.mtime) % WINDOWS_TICKS_PER_SEC)
							epoch, epoch_err := datetime.components_to_datetime(1601, 1, 1, 0, 0, 0, 0)
							assert(epoch_err == .None, "cannot convert windows epoch to datetime")

							epoch_time, epoch_time_ok := time.datetime_to_time(epoch)
							assert(epoch_time_ok, "cannot convert epoch to Time")

							modtime_duration := time.Duration(nsecs)
							actual_modtime := time.time_add(epoch_time, modtime_duration)
							modtime_to_datetime, modtime_to_datetime_ok := time.time_to_datetime(actual_modtime)
							if !modtime_to_datetime_ok {
								return .Datetime_Error
							}
							entry.modified_datetime = modtime_to_datetime
						}
					}
				case 0x000d:
					// UNIX
					{
						Extra_Unix :: struct #packed {
							atime: u32le,
							mtime: u32le,
							uid:   u16le,
							gid:   u16le,
						}
						variable_field_size := i64(extra_field_hdr.size) - size_of(Extra_Unix)
						unix_extra := reader_read_value(archive.reader, Extra_Unix) or_break
						// skip the variable field
						reader_skip(archive.reader, variable_field_size)
						mtime_unix := time.unix(i64(unix_extra.mtime), 0)
						unix_datetime, unix_datetime_err := time.time_to_datetime(mtime_unix)
						if !unix_datetime_err {
							return .Datetime_Error
						}
						entry.modified_datetime = unix_datetime
					}
				case:
					// There are others too (just ignore those)
					reader_skip(archive.reader, i64(extra_field_hdr.size))
				}

			}
		}

		// Skip the comment
		reader_skip(archive.reader, i64(cd_hdr.file_comment_length)) or_return

		is_dir := strings.ends_with(file_name, "/") || strings.ends_with(file_name, "\\")
		// If cannot determine from the path alone do a platform-dependent flags checks
		if !is_dir {
			// See 4.4.2
			host_system := i64(cd_hdr.version >> 8)
			if host_system == i64(Platform.MS_DOS) || host_system == i64(Platform.WINDOWS) {
				if (cd_hdr.external_attrib & 0x10) != 0 {
					is_dir = true
				}
			} else if host_system == i64(Platform.UNIX) {
				if ((cd_hdr.external_attrib >> 16) & 0x4000) != 0 {
					is_dir = true
				}
			}
		}

		entry.is_directory = is_dir
		entry.is_encrypted = (cd_hdr.flag & 0x1) != 0

		append(&archive.entries, entry)

	}

	return ZipError.None
}

stat_by_name :: proc(archive: ^ZipArchive, name: string) -> (entry: ZipEntry, idx: u64, err: ZipError) {
	for _entry, i in archive.entries {
		if _entry.name == name {
			return _entry, u64(i), .None
		}
	}

	return entry, idx, .Entry_Not_Found
}

stat_by_index :: proc(archive: ^ZipArchive, index: u64) -> (entry: ZipEntry, err: ZipError) {
	if int(index) > len(archive.entries) - 1 {
		return entry, .Entry_Not_Found
	}

	return archive.entries[index], .None
}

stat :: proc {
	stat_by_name,
	stat_by_index,
}


deflate_decompressor :: proc(input: []u8, allocator: mem.Allocator) -> (out: bytes.Buffer, err: ZipError) {
	out_buffer: bytes.Buffer
	bytes.buffer_init_allocator(&out_buffer, 0, len(input), allocator)
	zlib_err := zlib.inflate_from_byte_array_raw(input, &out_buffer)
	if zlib_err != {} {
		return out, .Deflate_Error
	}

	return out_buffer, ZipError.None
}

// Will allocate a new reader
extract_entry_to_reader :: proc {
	extract_entry_to_reader_by_name,
	extract_entry_to_reader_by_index,
}

extract_entry_to_reader_by_name :: proc(archive: ^ZipArchive, entry_name: string) -> (r: ^Reader, err: Error) {
	_, entry_idx := stat_by_name(archive, entry_name) or_return
	return extract_entry_to_reader_by_index(archive, entry_idx)
}

extract_entry_to_reader_by_index :: proc(archive: ^ZipArchive, entry_idx: u64) -> (r: ^Reader, err: Error) {
	target_entry := stat_by_index(archive, entry_idx) or_return
	reader_seek(archive.reader, i64(target_entry.local_offset)) or_return
	local_file_header := reader_read_value(archive.reader, _LfHdr) or_return
	if local_file_header.magic != u32le(Magic.LFH) {
		return nil, .Corrupted_Data
	}

	if target_entry.is_encrypted {
		// Refer to 6.1.3
		// 12 bytes as the encryption header
		// APPENDIX E - AE-x encryption marker
		unimplemented("implement AEX decryption")
	}

	// Ignore the file name and extra fields of the local header
	// Place the cursor right at start of file data
	skip_bytes := i64(local_file_header.file_name_len) + i64(local_file_header.extra_field_len)
	reader_skip(archive.reader, skip_bytes) or_return
	switch target_entry.method {
	case .DEFLATE:
		{
			assert(target_entry.compressed_size < target_entry.uncompressed_size)
			file_data := make([]u8, target_entry.compressed_size, archive.allocator)
			reader_read_array(archive.reader, file_data) or_return

			r = new(Reader, archive.allocator)
			out_buffer := deflate_decompressor(file_data, archive.allocator) or_return
			reader_init(r, out_buffer.buf[:])

			return r, ZipError.None
		}
	case .STORE:
		{
			assert(target_entry.compressed_size == target_entry.uncompressed_size)
			file_data := make([]u8, target_entry.uncompressed_size, archive.allocator)
			reader_read_array(archive.reader, file_data) or_return
			r = new(Reader, archive.allocator)

			reader_init(r, file_data)

			return r, ZipError.None
		}
	case .AEX:
		unreachable()
	}


	return nil, .Not_Supported
}

dos_datetime_to_datetime :: proc(date: MsDosDate, time: MsDosTime) -> datetime.DateTime {
	MS_DOS_YEAR_EPOCH :: 1980

	new_date, new_date_err := datetime.components_to_datetime(
		MS_DOS_YEAR_EPOCH + date.year,
		date.month,
		date.day,
		time.hour,
		time.minute,
		time.second,
	)

	assert(new_date_err == .None)
	return new_date
}

is_error :: proc(error: Error) -> bool {
	switch t in error {
	case ZipError:
		{
			if error.(ZipError) != ZipError.None {
				return true
			} else {
				return false
			}
		}
	case io.Error:
		{
			if error.(io.Error) != io.Error.None {
				return true
			} else {
				return false
			}
		}
	}

	return false
}

// Reads an entire file from the archive
read_file_all :: proc(
	archive: ^ZipArchive,
	allocator: mem.Allocator,
	name: string,
	passwd: string,
) -> (
	b: []byte,
	err: Error,
) {
	reader, reader_err := extract_entry_to_reader(archive, name)
	if is_error(reader_err) {
		return b, reader_err
	}

	total_data_size := reader_size(reader)
	b = make([]byte, total_data_size, allocator)
	reader_read_full(reader, b) or_return

	crc32_hash := hash.crc32(b)
	entry, _ := stat(archive, name) or_return

	if crc32_hash != entry.crc32 {
		return b, .Corrupted_Data
	}

	return b, ZipError.None
}
