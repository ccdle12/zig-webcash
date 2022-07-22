const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const test_runner = b.addTest("args.zig");

    const test_exe = b.addExecutable("demo", "demo.zig");

    const run_1 = test_exe.run();
    run_1.addArgs(&[_][]const u8{
        "--output", "demo", "--with-offset", "--signed_number=-10", "--unsigned_number", "20", "--mode", "slow", "help", "this", "is", "borked",
    });

    const test_step = b.step("test", "Runs the test suite.");
    test_step.dependOn(&test_runner.step);
    test_step.dependOn(&run_1.step);
}
