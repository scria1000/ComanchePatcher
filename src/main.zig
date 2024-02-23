const std = @import("std");
const testing = std.testing;
const process = std.process;
const path = std.fs.path;

const Allocator = std.mem.Allocator;

const usage =
    \\Usage: patcher [command] [arguments]
    \\
    \\Commands:
    \\
    \\  patch <target>               Patch Comanche Gold exe
    \\  copy <source> <destination>  Copy KDV.PFF from Comanche Gold CD directory
    \\
    \\Options:
    \\
    \\  -?, -h, --help               Print usage text.
    \\
    \\Examples:
    \\
    \\  patcher patch
    \\  patcher patch Wc3.exe
    \\  patcher patch "C:\Comanche Gold\Wc3.exe"
    \\
    \\  patcher copy E:\ .
    \\  patcher copy E:\ KDV.PFF
    \\  patcher copy E:\C3G\KDV.PFF "C:\Games\Comanche Gold\KDV.PFF"
    \\
    \\
;

const PaternError = blk: {
    var errors: [Patterns.len]std.builtin.Type.Error = undefined;
    for (0..Patterns.len) |i| {
        errors[i] = .{ .name = std.fmt.comptimePrint("Pattern{d}NotFound", .{i + 1}) };
    }
    break :blk @Type(.{ .ErrorSet = &errors });
};

const Patterns = .{
    &[1]u8{0x81},
    "CDFSt",
    &[1]u8{0xAA},
};

const Patch = .{
    &[1]u8{0x83},
    &[5]u8{ 0x00, 0x90, 0x90, 0x90, 0x75 },
    &[1]u8{0x7D},
};

const KDV_PFF_len = 175093640;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const args = try process.argsAlloc(allocator);

    return mainArgs(allocator, args);
}

fn mainArgs(allocator: Allocator, args: []const []const u8) !void {
    if (args.len <= 1) {
        patchExe(allocator, &.{}) catch |err| {
            std.log.err("{s}", .{@errorName(err)});
            try printEnterContinue();
            process.exit(1);
        };
        return printEnterContinue();
    }

    const cmd = args[1];
    const cmd_args = args[2..];

    if (std.mem.eql(u8, cmd, "patch")) {
        return patchExe(allocator, cmd_args);
    } else if ((std.mem.eql(u8, cmd, "copy"))) {
        return copyResource(allocator, cmd_args);
    } else if (std.mem.eql(u8, cmd, "help") or
        std.mem.eql(u8, cmd, "-?") or
        std.mem.eql(u8, cmd, "-h") or
        std.mem.eql(u8, cmd, "--help"))
    {
        return std.io.getStdOut().writeAll(usage);
    } else if (path.isAbsolute(cmd)) {
        patchExe(allocator, &.{cmd}) catch |err| {
            std.log.err("{s}", .{@errorName(err)});
            try printEnterContinue();
            process.exit(1);
        };
        return printEnterContinue();
    } else {
        try std.io.getStdOut().writeAll(usage);
        fatal("unknown command: {s}", .{args[1]});
    }
}

fn patchExe(allocator: Allocator, args: []const []const u8) !void {
    const current_dir = try getcwdAlloc(allocator);
    defer allocator.free(current_dir);

    const dest_path_resolved = try path.resolve(allocator, &.{ current_dir, if (args.len < 1)
        "Wc3.exe"
    else
        args[0] });
    defer allocator.free(dest_path_resolved);

    var file = try std.fs.openFileAbsolute(dest_path_resolved, .{ .mode = .read_write });
    defer file.close();

    const offsets = try getOffsets(file);

    try file.seekTo(offsets[0]);
    _ = try file.write(Patch[0]);

    try file.seekTo(offsets[1]);
    _ = try file.write(Patch[1]);

    try file.seekTo(offsets[2]);
    _ = try file.write(Patch[2]);

    std.debug.print("Success!\n", .{});
}

fn getOffsets(stream: anytype) !struct { u64, u64, u64 } {
    var buffered_reader = std.io.bufferedReaderSize(2048, stream.reader());

    var previous_read_buffer: [2048]u8 = undefined;

    var offset_1: u64 = 0;
    var offset_2: u64 = 0;
    var offset_3: u64 = 0;

    while (true) {
        const reader = buffered_reader.reader();

        var read_buffer: [2048]u8 = undefined;
        const read = try reader.readAll(&read_buffer);
        defer previous_read_buffer = read_buffer;
        if (read == 0) break;

        const bytes: [4096]u8 = previous_read_buffer ++ read_buffer;

        const file_position = try stream.getPos();

        if (offset_2 == 0) {
            if (std.mem.indexOf(u8, &read_buffer, Patterns[1])) |index_1| {
                offset_2 = (file_position - read) + index_1;

                if (index_1 >= 3) {
                    offset_1 = if (std.mem.eql(u8, Patterns[0], &[1]u8{read_buffer[index_1 - 3]}))
                        offset_2 - 3
                    else
                        return PaternError.Pattern1NotFound;
                } else {
                    offset_1 = if (std.mem.eql(u8, Patterns[0], &.{previous_read_buffer[previous_read_buffer.len - (3 - index_1)]}))
                        offset_2 - 3
                    else
                        return PaternError.Pattern1NotFound;
                }

                if (index_1 + 5 >= read_buffer.len) {
                    continue;
                } else {
                    offset_3 = if (std.mem.indexOfPos(u8, &read_buffer, index_1 + 5, Patterns[2])) |index_2|
                        (file_position - read) + index_2
                    else
                        continue;
                    break;
                }
            } else if (std.mem.indexOf(u8, &bytes, Patterns[1])) |index_1| {
                offset_2 = file_position - 2048 + index_1 - read;
                offset_1 = if (std.mem.eql(u8, Patterns[0], &.{bytes[index_1 - 3]}))
                    offset_2 - 3
                else
                    return PaternError.Pattern1NotFound;
            } else continue;
        }

        if (offset_3 == 0) {
            offset_3 = if (std.mem.indexOf(u8, &read_buffer, Patterns[2])) |index|
                (file_position - read) + index
            else
                continue;
            break;
        }
    }

    const offsets = .{ offset_1, offset_2, offset_3 };

    inline for (offsets, 0..) |offset, i| {
        if (offset == 0) {
            return @field(PaternError, std.fmt.comptimePrint("Pattern{d}NotFound", .{i + 1}));
        }
    }

    return offsets;
}

fn copyResource(allocator: Allocator, args: []const []const u8) !void {
    if (args.len < 2) {
        try std.io.getStdOut().writeAll(usage);
        fatal("expected a positional argument", .{});
    }

    const current_dir = try getcwdAlloc(allocator);
    defer allocator.free(current_dir);

    const source_path_resolved = try path.resolve(allocator, if (std.ascii.eqlIgnoreCase("KDV.PFF", path.basename(args[0])))
        &.{args[0]}
    else
        &.{ args[0], "c3g" ++ path.sep_str ++ "kdv.pff" });
    defer allocator.free(source_path_resolved);

    const dest_path_resolved = try path.resolve(allocator, &.{ current_dir, args[1], "KDV.PFF" });
    defer allocator.free(dest_path_resolved);

    var read_file = try std.fs.openFileAbsolute(source_path_resolved, .{ .mode = .read_only });
    defer read_file.close();

    var write_file = try std.fs.createFileAbsolute(dest_path_resolved, .{});
    defer write_file.close();

    var buffered_reader = std.io.bufferedReaderSize(64000, read_file.reader());
    var counting_reader = std.io.countingReader(buffered_reader.reader());
    var reader = counting_reader.reader();

    var buffered_writer = bufferedWriterSize(64000, write_file.writer());
    var writer = buffered_writer.writer();

    while (true) {
        var buf: [64000]u8 = undefined;
        const read = try reader.readAll(&buf);
        if (counting_reader.bytes_read >= KDV_PFF_len) {
            const range_end = read -| (counting_reader.bytes_read -| KDV_PFF_len);
            try writer.writeAll(buf[0..@intCast(range_end)]);
            break;
        } else {
            try writer.writeAll(&buf);
        }
    }

    try buffered_writer.flush();

    std.debug.print("Success!\n", .{});
}

fn getcwdAlloc(allocator: Allocator) ![]u8 {
    var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    return allocator.dupe(u8, try std.os.getcwd(&buf));
}

fn bufferedWriterSize(comptime size: usize, writer: anytype) std.io.BufferedWriter(size, @TypeOf(writer)) {
    return .{ .unbuffered_writer = writer };
}

fn printEnterContinue() !void {
    try std.io.getStdOut().writeAll("Press ENTER to continue...");
    var buf: [1]u8 = undefined;
    _ = std.io.getStdIn().read(&buf) catch 0;
}

fn fatal(comptime format: []const u8, args: anytype) noreturn {
    std.log.err(format, args);
    process.exit(1);
}

const beginning = [_]u8{
    0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
    0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00,
    0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
    0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
    0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
    0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24,
};

const end = [_]u8{
    0x81, 0x00, 0x00, 0x43, 0x44, 0x46, 0x53, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

test "Alignment test 1" {
    const bytes = beginning ++ [1]u8{0} ** 1148 ++ end;

    var fbs = std.io.fixedBufferStream(&bytes);
    const offsets = try getOffsets(&fbs);

    std.debug.print("Bytes len: {d}\n", .{bytes.len});
    try testing.expectEqualSlices(u8, Patterns[1], bytes[offsets[1] .. offsets[1] + 5]);
    try testing.expectEqualSlices(u8, Patterns[0], &.{bytes[offsets[0]]});
    try testing.expectEqualSlices(u8, Patterns[2], &.{bytes[offsets[2]]});
}

test "Alignment test 2" {
    const bytes = beginning ++ [1]u8{0} ** 1148 ++ end ++ [1]u8{0} ** 1030;

    var fbs = std.io.fixedBufferStream(&bytes);
    const offsets = try getOffsets(&fbs);

    std.debug.print("Bytes len: {d}\n", .{bytes.len});
    try testing.expectEqualSlices(u8, Patterns[1], bytes[offsets[1] .. offsets[1] + 5]);
    try testing.expectEqualSlices(u8, Patterns[0], &.{bytes[offsets[0]]});
    try testing.expectEqualSlices(u8, Patterns[2], &.{bytes[offsets[2]]});
}

test "Alignment test 3" {
    const bytes = [1]u8{0} ** 400 ++ beginning ++ [1]u8{0} ** 1148 ++ end;

    var fbs = std.io.fixedBufferStream(&bytes);
    const offsets = try getOffsets(&fbs);

    std.debug.print("Bytes len: {d}\n", .{bytes.len});
    try testing.expectEqualSlices(u8, Patterns[1], bytes[offsets[1] .. offsets[1] + 5]);
    try testing.expectEqualSlices(u8, Patterns[0], &.{bytes[offsets[0]]});
    try testing.expectEqualSlices(u8, Patterns[2], &.{bytes[offsets[2]]});
}

test "Alignment test 4" {
    const bytes = [1]u8{0} ** 800 ++ beginning ++ [1]u8{0} ** 1148 ++ end;

    var fbs = std.io.fixedBufferStream(&bytes);
    const offsets = try getOffsets(&fbs);

    std.debug.print("Bytes len: {d}\n", .{bytes.len});
    try testing.expectEqualSlices(u8, Patterns[1], bytes[offsets[1] .. offsets[1] + 5]);
    try testing.expectEqualSlices(u8, Patterns[0], &.{bytes[offsets[0]]});
    try testing.expectEqualSlices(u8, Patterns[2], &.{bytes[offsets[2]]});
}

test "Alignment test 5" {
    const bytes = [1]u8{0} ** 300 ++ beginning ++ [1]u8{0} ** 1148 ++ end;

    var fbs = std.io.fixedBufferStream(&bytes);
    const offsets = try getOffsets(&fbs);

    std.debug.print("Bytes len: {d}\n", .{bytes.len});
    try testing.expectEqualSlices(u8, Patterns[1], bytes[offsets[1] .. offsets[1] + 5]);
    try testing.expectEqualSlices(u8, Patterns[0], &.{bytes[offsets[0]]});
    try testing.expectEqualSlices(u8, Patterns[2], &.{bytes[offsets[2]]});
}

test "Alignment test 6" {
    const bytes = [1]u8{0} ** 776 ++ beginning ++ [1]u8{0} ** 1148 ++ end;

    var fbs = std.io.fixedBufferStream(&bytes);
    const offsets = try getOffsets(&fbs);

    std.debug.print("Bytes len: {d}\n", .{bytes.len});
    try testing.expectEqualSlices(u8, Patterns[1], bytes[offsets[1] .. offsets[1] + 5]);
    try testing.expectEqualSlices(u8, Patterns[0], &.{bytes[offsets[0]]});
    try testing.expectEqualSlices(u8, Patterns[2], &.{bytes[offsets[2]]});
}

test "Alignment test 7" {
    const bytes = [1]u8{0} ** 774 ++ beginning ++ [1]u8{0} ** 1148 ++ end;

    var fbs = std.io.fixedBufferStream(&bytes);
    const offsets = try getOffsets(&fbs);

    std.debug.print("Bytes len: {d}\n", .{bytes.len});
    try testing.expectEqualSlices(u8, Patterns[1], bytes[offsets[1] .. offsets[1] + 5]);
    try testing.expectEqualSlices(u8, Patterns[0], &.{bytes[offsets[0]]});
    try testing.expectEqualSlices(u8, Patterns[2], &.{bytes[offsets[2]]});
}

test "Alignment test 8" {
    const bytes = [1]u8{0} ** 7536 ++ beginning ++ [1]u8{0} ** 4625 ++ end ++ [1]u8{0} ** 3672;

    var fbs = std.io.fixedBufferStream(&bytes);
    const offsets = try getOffsets(&fbs);

    std.debug.print("Bytes len: {d}\n", .{bytes.len});
    try testing.expectEqualSlices(u8, Patterns[1], bytes[offsets[1] .. offsets[1] + 5]);
    try testing.expectEqualSlices(u8, Patterns[0], &.{bytes[offsets[0]]});
    try testing.expectEqualSlices(u8, Patterns[2], &.{bytes[offsets[2]]});
}

test "Random alignment test" {
    var seed: u64 = undefined;
    try std.os.getrandom(std.mem.asBytes(&seed));

    var prng = std.rand.DefaultPrng.init(seed);
    const rand = &prng.random();

    const buf: [8192]u8 = undefined;

    for (0..100000) |i| {
        std.debug.print("Loop {d}\n", .{i});

        const random_buf = buf[0..rand.uintAtMost(u16, 8192)];
        const random_buf_2 = buf[0..rand.uintAtMost(u16, 8192)];
        const random_buf_3 = buf[0..rand.uintAtMost(u16, 8192)];

        const bytes = try std.mem.concat(testing.allocator, u8, &.{ random_buf, &beginning, random_buf_2, &end, random_buf_3 });
        defer testing.allocator.free(bytes);

        var fbs = std.io.fixedBufferStream(bytes);
        const offsets = getOffsets(&fbs) catch |err| {
            var file = try std.fs.cwd().createFile("test_bytes_random", .{});
            defer file.close();

            try file.writeAll(bytes);

            return err;
        };

        testing.expectEqualSlices(u8, Patterns[1], bytes[offsets[1] .. offsets[1] + 5]) catch |err| {
            var file = try std.fs.cwd().createFile("test_bytes_random", .{});
            defer file.close();

            try file.writeAll(bytes);

            return err;
        };

        testing.expectEqualSlices(u8, Patterns[0], &.{bytes[offsets[0]]}) catch |err| {
            var file = try std.fs.cwd().createFile("test_bytes_random", .{});
            defer file.close();

            try file.writeAll(bytes);

            return err;
        };

        testing.expectEqualSlices(u8, Patterns[2], &.{bytes[offsets[2]]}) catch |err| {
            var file = try std.fs.cwd().createFile("test_bytes_random", .{});
            defer file.close();

            try file.writeAll(bytes);

            return err;
        };
    }
}
