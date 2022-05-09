const std = @import("std");

const args = @import("args");
const crypto = std.crypto;
const fs = std.fs;
const fmt = std.fmt;
const io = std.io;
const json = std.json;
const mem = std.mem;
const testing = std.testing;

const ArrayList = std.ArrayList;
const AutoHashMap = std.hash_map.AutoHashMap;
const File = std.fs.File;

pub const wallet_name = "default_wallet.webcash";

pub const ChainCode = enum(u8) {
    receive = 0,
    pay = 1,
    change = 2,
    mining = 3,

    const items = [_]ChainCode{
        ChainCode.receive,
        ChainCode.pay,
        ChainCode.change,
        ChainCode.mining,
    };

    pub const ChainCodeError = error{
        InvalidVariant,
    };

    pub fn get_key(self: ChainCode) []const u8 {
        return switch (self) {
            ChainCode.receive => "RECEIVE",
            ChainCode.pay => "PAY",
            ChainCode.change => "CHANGE",
            ChainCode.mining => "MINING",
        };
    }

    // TODO: make input to upper or lower
    pub fn from_str(input: []const u8) !ChainCode {
        if (mem.eql(u8, input, "RECEIVE")) {
            return ChainCode.receive;
        }

        if (mem.eql(u8, input, "PAY")) {
            return ChainCode.pay;
        }

        if (mem.eql(u8, input, "CHANGE")) {
            return ChainCode.change;
        }

        if (mem.eql(u8, input, "MINING")) {
            return ChainCode.mining;
        }

        return ChainCodeError.InvalidVariant;
    }
};

pub const Legalese = enum {
    terms,

    const items = [_]Legalese{Legalese.terms};

    pub const LegaleseError = error{
        InvalidVariant,
    };

    pub fn get_key(self: Legalese) []const u8 {
        return switch (self) {
            Legalese.terms => "terms",
        };
    }

    pub fn get_value(self: Legalese) []const u8 {
        return switch (self) {
            Legalese.terms => "I acknowledge and agree to the Terms of Service located at https://webcash.org/terms",
        };
    }

    pub fn from_str(input: []const u8) !Legalese {
        if (mem.eql(u8, input, "terms")) {
            return Legalese.terms;
        }

        return LegaleseError.InvalidVariant;
    }
};

fn gen_new_master_secret() [32]u8 {
    var secret_seed: [32]u8 = undefined;
    crypto.random.bytes(&secret_seed);
    return secret_seed;
}

// TODO: Replace types for log, webcash and unconfirmed, once I figure out
// their usecase.
pub const Wallet = struct {
    version: u32 = 1,

    // TODO: Required to require the ack of the user per legal term.
    legal_acks: AutoHashMap(Legalese, bool),

    // TODO:?
    log: []const u8,

    // TODO:?
    webcash: []const u8,

    // TODO:?
    unconfirmed: []const u8,

    // TODO:?
    master_secret: [32]u8,

    // TODO:?
    wallet_depths: AutoHashMap(ChainCode, u32),

    gpa: *mem.Allocator,

    pub fn init(gpa: *mem.Allocator) !Wallet {
        var legal_acks = AutoHashMap(Legalese, bool).init(gpa);
        for (Legalese.items) |item| try legal_acks.put(item, false);

        var wallet_depths = AutoHashMap(ChainCode, u32).init(gpa);
        for (ChainCode.items) |code| try wallet_depths.put(code, 0);

        return Wallet{
            .log = "foo",
            .legal_acks = legal_acks,
            .webcash = "foo",
            .unconfirmed = "foo",
            .master_secret = gen_new_master_secret(),
            .wallet_depths = wallet_depths,
            .gpa = gpa,
        };
    }

    pub fn deinit(self: *Wallet) void {
        self.legal_acks.deinit();
        self.wallet_depths.deinit();
    }

    pub fn json_str(self: @This(), writer: anytype) !void {
        var json_map = json.ObjectMap.init(self.gpa);
        defer json_map.deinit();

        try json_map.putNoClobber("log", .{ .String = self.log });

        var legalese = json.ObjectMap.init(self.gpa);
        defer legalese.deinit();

        var legal_acks_iter = self.legal_acks.iterator();
        while (legal_acks_iter.next()) |entry| {
            try legalese.putNoClobber(entry.key_ptr.*.get_key(), .{
                .Bool = entry.value_ptr.*,
            });
        }
        try json_map.putNoClobber("legalese", .{ .Object = legalese });

        try json_map.putNoClobber("webcash", .{ .String = self.webcash });
        try json_map.putNoClobber("unconfirmed", .{ .String = self.unconfirmed });
        try json_map.putNoClobber("master_secret", .{
            .String = &self.master_secret,
        });

        var wallet_depths = std.json.ObjectMap.init(self.gpa);
        defer wallet_depths.deinit();

        var wallet_depths_iter = self.wallet_depths.iterator();
        while (wallet_depths_iter.next()) |entry| {
            try wallet_depths.putNoClobber(entry.key_ptr.*.get_key(), .{
                .Integer = entry.value_ptr.*,
            });
        }
        try json_map.putNoClobber("walletdepths", .{ .Object = wallet_depths });

        try (std.json.Value{ .Object = json_map }).jsonStringify(.{}, writer);
    }

    pub fn save(self: @This(), file_name: []const u8) !void {
        var str = std.ArrayList(u8).init(self.gpa);
        defer str.deinit();
        try self.json_str(str.writer());

        const file = try fs.cwd().createFile(
            file_name,
            File.CreateFlags{ .read = true },
        );
        defer file.close();

        _ = try file.write(str.items);
    }

    pub fn load(gpa: *mem.Allocator, file_name: []const u8) !Wallet {
        var file = try fs.cwd().openFile(file_name, .{ .read = true });
        defer file.close();

        var str: [1024]u8 = undefined;
        const num_read = try file.readAll(&str);

        var parser = std.json.Parser.init(gpa, false);
        defer parser.deinit();

        var tree = try parser.parse(str[0..num_read]);
        defer tree.deinit();

        const log = tree.root.Object.get("log").?.String;
        var legalese_iter = tree.root.Object.get("legalese").?.Object.iterator();
        const webcash = tree.root.Object.get("webcash").?.String;
        const unconfirmed = tree.root.Object.get("unconfirmed").?.String;
        var wallet_depths_iter = tree.root.Object.get("walletdepths").?.Object.iterator();

        var master_secret: [32]u8 = undefined;
        for (tree.root.Object.get("master_secret").?.Array.items) |item, index| {
            if (index > master_secret.len) break;
            master_secret[index] = @intCast(u8, item.Integer);
        }

        var legal_acks = AutoHashMap(Legalese, bool).init(gpa);
        errdefer legal_acks.deinit();
        while (legalese_iter.next()) |entry| {
            const key = try Legalese.from_str(entry.key_ptr.*);
            try legal_acks.put(key, entry.value_ptr.*.Bool);
        }

        var wallet_depths = AutoHashMap(ChainCode, u32).init(gpa);
        errdefer wallet_depths.deinit();
        while (wallet_depths_iter.next()) |entry| {
            const key = try ChainCode.from_str(entry.key_ptr.*);
            try wallet_depths.put(key, @intCast(u32, entry.value_ptr.*.Integer));
        }

        return Wallet{
            .log = log,
            .legal_acks = legal_acks,
            .webcash = webcash,
            .unconfirmed = unconfirmed,
            .master_secret = master_secret,
            .wallet_depths = wallet_depths,
            .gpa = gpa,
        };
    }
};

pub fn prompt_legal_acks(wallet: *Wallet) !void {
    if (check_legal_agreements(wallet)) {
        std.debug.print(
            "User has already agreed and acknowledged the disclosures.\n",
            .{},
        );
    } else {
        for (Legalese.items) |item| {
            std.debug.print("Discloure {s}: {s}\n", .{ item.get_key(), item.get_value() });

            const stdin = io.getStdIn().reader();
            const stdout = io.getStdOut().writer();

            try stdout.print("Do you agree? (y/n): ", .{});

            var buf: [10]u8 = undefined;
            if (try stdin.readUntilDelimiterOrEof(&buf, '\n')) |user_input| {
                if (mem.eql(u8, user_input, "y")) {
                    try wallet.legal_acks.put(item, true);
                } else {
                    std.debug.print(
                        "Unfortunately, you must acknowledge and agree to all agreements to use webcash.\n",
                        .{},
                    );
                }
            }
        }
    }

    std.debug.print("\n\n\nAll done! You've acknowledged all the disclosures. You may now use webcash.\n", .{});
}

pub fn check_legal_agreements(wallet: *Wallet) bool {
    for (Legalese.items) |item| {
        // TODO: Actually should panic or comptime exit?
        const ack = wallet.legal_acks.get(item) orelse return false;
        if (!ack) return false;
    }

    return true;
}

pub fn file_exists(file_name: []const u8) bool {
    var file = fs.cwd().openFile(file_name, .{}) catch {
        return false;
    };
    defer file.close();

    return true;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    // TODO: Is there a better way to do this?
    var wallet = blk: {
        if (!file_exists(wallet_name)) {
            var wallet = try Wallet.init(&gpa.allocator);

            try prompt_legal_acks(&wallet);
            try wallet.save(wallet_name);

            break :blk wallet;
        } else {
            var wallet = try Wallet.load(&gpa.allocator, wallet_name);
            break :blk wallet;
        }
    };

    defer wallet.deinit();

    const options = try args.parseForCurrentProcess(struct {
        // This declares long options for double hyphen
        output: ?[]const u8 = null,
        @"with-offset": bool = false,
        @"with-hexdump": bool = false,
        @"intermix-source": bool = false,
        numberOfBytes: ?i32 = null,
        signed_number: ?i64 = null,
        unsigned_number: ?u64 = null,
        mode: enum { default, special, slow, fast } = .default,

        // This declares short-hand options for single hyphen
        pub const shorthands = .{
            .S = "intermix-source",
            .b = "with-hexdump",
            .O = "with-offset",
            .o = "output",
        };
    }, &gpa.allocator, .print);
    defer options.deinit();

    std.debug.print("executable name: {s}\n", .{options.executable_name});
}

test "create and load wallet" {
    var wallet = try Wallet.init(testing.allocator);
    defer wallet.deinit();

    try wallet.save("tmp-test-wallet");

    var loaded_wallet = try Wallet.load(testing.allocator, "tmp-test-wallet");
    defer loaded_wallet.deinit();

    try testing.expectEqualSlices(u8, wallet.log, loaded_wallet.log);
    try testing.expectEqualSlices(u8, wallet.webcash, loaded_wallet.webcash);
    try testing.expectEqualSlices(u8, wallet.unconfirmed, loaded_wallet.unconfirmed);
    try testing.expectEqualSlices(u8, &wallet.master_secret, &loaded_wallet.master_secret);

    for (Legalese.items) |item| {
        try testing.expect(wallet.legal_acks.contains(item));
        try testing.expect(loaded_wallet.legal_acks.contains(item));
    }

    for (ChainCode.items) |item| {
        try testing.expect(wallet.wallet_depths.contains(item));
        try testing.expect(loaded_wallet.wallet_depths.contains(item));
    }

    try fs.cwd().deleteFile("tmp-test-wallet");
}
