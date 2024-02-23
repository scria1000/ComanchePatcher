const std = @import("std");
const builtin = @import("builtin");

const Step = std.Build.Step;
const LazyPath = std.Build.LazyPath;
const InstallDir = std.Build.InstallDir;

const e_lfanew: u32 = 0x3c;

const CoffHeader = extern struct {
    Magic: u32 align(8) = 0x00004550,
    Machine: u16 = 0,
    NumberOfSections: u16 = 0,
    TimeDateStamp: u32 = 0,
    PointerToSymbolTable: u32 = 0,
    NumberOfSymbols: u32 = 0,
    SizeOfOptionalHeader: u16 = 0,
    Characteristics: u16 = 0,
    OptionalHeader: OptionalHeader,
};

const OptionalHeader = extern struct {
    Magic: PEFormat align(8),
    NotNeeded: [38]u8,
    MajorMinorVersion: MajorMinorVersion,
};

const PEFormat = enum(u16) {
    PE32 = 0x10B,
    PE32Plus = 0x20B,
};

const MajorMinorVersion = extern struct {
    MajorOperatingSystemVersion: u16 align(8),
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
};

pub fn build(b: *std.Build) !void {
    b.reference_trace = 10;

    const build_msvc = builtin.os.tag == .windows and b.option(bool, "msvc", "Build against MSVC") orelse false;

    const target = b.standardTargetOptions(.{ .default_target = .{
        .cpu_arch = .x86,
        .cpu_model = .baseline,
        .os_tag = .windows,
        .os_version_min = if (build_msvc) .{ .windows = .xp } else .{ .windows = .win10_fe },
        .os_version_max = .none,
        .abi = if (build_msvc) .msvc else .gnu,
    } });

    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });

    const target_os_tag = if (@hasDecl(std.Build, "ResolvedTarget")) target.result.os.tag else target.getOsTag();

    const exe = b.addExecutable(.{
        .name = "patcher",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
        .single_threaded = if (target_os_tag == .windows) true else false,
        .link_libc = if (target_os_tag == .windows) true else false,
        .linkage = if (target_os_tag == .windows) .static else .dynamic,
    });

    if (@hasDecl(std, "Build") and
        @hasDecl(std.Build, "Step") and
        @hasDecl(std.Build.Step, "Compile"))
    {
        if (@hasField(std.Build.Step.Compile, "win32_manifest")) {
            exe.win32_manifest = .{ .path = "patcher.manifest" };
        }
    }

    if (build_msvc) {
        switch (if (@hasDecl(std.Build, "ResolvedTarget")) target.result.cpu.arch else target.getCpuArch()) {
            .x86 => exe.setLibCFile(.{ .path = "msvctools-x86.txt" }),
            .x86_64 => exe.setLibCFile(.{ .path = "msvctools-x64.txt" }),
            else => {},
        }
    }

    const install_step = b.addInstallArtifact(exe, .{});

    b.getInstallStep().dependOn(&install_step.step);

    if (target_os_tag == .windows) {
        const modify_header_step = modifyRequiredOsVersion(b, install_step);

        b.getInstallStep().dependOn(modify_header_step);
    }
}

fn modifyRequiredOsVersion(owner: *std.Build, install_artifact: *Step.InstallArtifact) *Step {
    const ModifyRequiredOsVersion = struct {
        step: Step,
        install_artifact: *Step.InstallArtifact,

        pub fn make(step: *Step, prog_node: *std.Progress.Node) anyerror!void {
            _ = prog_node;

            const self = @fieldParentPtr(@This(), "step", step);
            const dest_builder = self.install_artifact.step.owner;
            const full_dest_path = dest_builder.getInstallPath(self.install_artifact.dest_dir.?, self.install_artifact.dest_sub_path);

            const file = try std.fs.openFileAbsolute(full_dest_path, .{ .mode = .read_write });
            defer file.close();

            const reader = file.reader();

            try file.seekTo(e_lfanew);

            const coff_header_offset = try reader.readInt(u32, if (@hasField(std.builtin.Endian, "little")) .little else .Little);
            try file.seekTo(coff_header_offset);

            var coff_header_struct = try reader.readStruct(CoffHeader);
            coff_header_struct.OptionalHeader.MajorMinorVersion.MajorOperatingSystemVersion = 5;
            coff_header_struct.OptionalHeader.MajorMinorVersion.MajorSubsystemVersion = 5;

            const writer = file.writer();

            const file_position = try file.getPos();

            try file.seekTo(file_position - @sizeOf(MajorMinorVersion));
            try writer.writeStruct(coff_header_struct.OptionalHeader.MajorMinorVersion);
        }
    };

    const self: *ModifyRequiredOsVersion = owner.allocator.create(ModifyRequiredOsVersion) catch @panic("OOM");
    self.* = .{
        .step = Step.init(.{
            .id = .custom,
            .name = owner.fmt("Enable executable compatibility for Windows XP", .{}),
            .owner = owner,
            .makeFn = ModifyRequiredOsVersion.make,
        }),
        .install_artifact = install_artifact,
    };
    self.step.dependOn(&install_artifact.step);
    return &self.step;
}
