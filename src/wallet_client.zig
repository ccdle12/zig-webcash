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
const fmtSliceHexLower = fmt.fmtSliceHexLower;
const random = crypto.random;
const hexToBytes = fmt.hexToBytes;
const Sha256 = crypto.hash.sha2.Sha256;

pub const wallet_name = "default_wallet.webcash";

pub const U256 = [32]u8;

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

pub const LogType = enum {
    insert,

    pub const LogTypeError = error{
        InvalidVariant,
    };

    pub fn get_key(self: LogType) []const u8 {
        return switch (self) {
            LogType.insert => "insert",
        };
    }

    // TODO: make input to upper or lower
    pub fn from_str(input: []const u8) !LogType {
        if (mem.eql(u8, input, "insert")) {
            return LogType.insert;
        }

        return LogTypeError.InvalidVariant;
    }
};

pub const LogItem = struct {
    // TODO: doc comment
    log_type: LogType,

    // TODO: doc comment
    memo: ?[]const u8,

    // TODO: doc comment
    // TODO: Is u64 correct?
    amount: u64,

    // TODO: doc comment
    input_webcash: []const u8,

    // TODO: doc comment
    output_webcash: []const u8,

    /// Serializes the LogItem to a JSON map.
    pub fn to_json_map(self: LogItem, json_map: *json.ObjectMap) !void {
        try json_map.putNoClobber("type", .{ .String = self.log_type.get_key() });

        // TODO: Use memo optional instead of empty string
        try json_map.putNoClobber("memo", .{ .String = "" });
        try json_map.putNoClobber("amount", .{ .Integer = @intCast(i64, self.amount) });

        try json_map.putNoClobber("input_webcash", .{ .String = self.input_webcash });
        try json_map.putNoClobber("output_webcash", .{ .String = self.output_webcash });
    }

    // Deserialize a JSON map to a LogItem.
    pub fn from_json_map(json_map: *json.ObjectMap) !LogItem {
        return LogItem{
            .log_type = try LogType.from_str(json_map.get("type").?.String),
            .memo = json_map.get("memo").?.String,
            .amount = @intCast(u64, json_map.get("amount").?.Integer),
            .input_webcash = json_map.get("input_webcash").?.String,
            .output_webcash = json_map.get("output_webcash").?.String,
        };
    }
};

// TODO: Replace types for log, webcash and unconfirmed, once I figure out
// their usecase.
pub const Wallet = struct {
    version: u32 = 1,

    // TODO: Required to require the ack of the user per legal term.
    legal_acks: AutoHashMap(Legalese, bool),

    log: ArrayList(LogItem),

    // TODO:?
    webcash: ArrayList(SecretWebcash),

    // TODO:?
    unconfirmed: ArrayList(SecretWebcash),

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

        // TODO: Se/Deserialize log correctly
        return Wallet{
            .log = ArrayList(LogItem).init(gpa),
            .legal_acks = legal_acks,
            .webcash = ArrayList(SecretWebcash).init(gpa),
            // TODO:
            // .unconfirmed = "",
            .unconfirmed = ArrayList(SecretWebcash).init(gpa),
            .master_secret = gen_new_master_secret(),
            .wallet_depths = wallet_depths,
            .gpa = gpa,
        };
    }

    pub fn deinit(self: *Wallet) void {
        self.legal_acks.deinit();
        self.wallet_depths.deinit();
        self.webcash.deinit();

        // TODO:
        self.unconfirmed.deinit();

        // TODO:
        self.log.deinit();
    }

    pub fn json_str(self: @This(), alloc: *mem.Allocator, writer: anytype) !void {
        var json_map = json.ObjectMap.init(alloc);

        var log = blk: {
            var arr = json.Array.init(alloc);
            for (self.log.items) |log| {
                var log_map = json.ObjectMap.init(alloc);
                try log.to_json_map(&log_map);

                try arr.append(.{ .Object = log_map });
            }

            break :blk arr;
        };
        try json_map.putNoClobber("log", .{ .Array = log });

        var legalese = blk: {
            var map = json.ObjectMap.init(alloc);

            var iter = self.legal_acks.iterator();
            while (iter.next()) |entry| {
                try map.putNoClobber(entry.key_ptr.*.get_key(), .{
                    .Bool = entry.value_ptr.*,
                });
            }

            break :blk map;
        };
        try json_map.putNoClobber("legalese", .{ .Object = legalese });

        // TODO: Function or anonymous function???
        var webcash = blk: {
            var arr = json.Array.init(alloc);

            for (self.webcash.items) |webcash| {
                var str = try webcash.to_str(alloc);
                try arr.append(.{ .String = str.items });
            }

            break :blk arr;
        };
        try json_map.putNoClobber("webcash", .{ .Array = webcash });

        // TODO:
        // try json_map.putNoClobber("unconfirmed", .{ .String = self.unconfirmed });
        var unconfirmed = blk: {
            var arr = json.Array.init(alloc);

            for (self.unconfirmed.items) |unconfirmed| {
                var str = try unconfirmed.to_str(alloc);
                try arr.append(.{ .String = str.items });
            }

            break :blk arr;
        };
        try json_map.putNoClobber("unconfirmed", .{ .Array = unconfirmed });

        var master_secret = blk: {
            var list = std.ArrayList(u8).init(alloc);
            try list.writer().print("{}", .{fmtSliceHexLower(&self.master_secret)});

            break :blk list;
        };
        try json_map.putNoClobber("master_secret", .{ .String = master_secret.items });

        var wallet_depths = blk: {
            var map = std.json.ObjectMap.init(alloc);

            var iter = self.wallet_depths.iterator();
            while (iter.next()) |entry| {
                try map.putNoClobber(entry.key_ptr.*.get_key(), .{
                    .Integer = entry.value_ptr.*,
                });
            }

            break :blk map;
        };
        try json_map.putNoClobber("walletdepths", .{ .Object = wallet_depths });

        try (std.json.Value{ .Object = json_map }).jsonStringify(.{}, writer);
    }

    pub fn save(self: @This(), file_name: []const u8) !void {
        const file = try fs.cwd().createFile(file_name, .{});
        defer file.close();

        // The JSON string is short-lived, meaning I just want to generate the
        // JSON String, write to file and throw it away. The arena allocator
        // is used so that we can throw everything on to this heap and deinit all
        // of it after use. Is there a better way to do this?
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        try self.json_str(&arena.allocator, file.writer());
    }

    pub fn load(gpa: *mem.Allocator, file_name: []const u8) !Wallet {
        var file = try fs.cwd().openFile(file_name, .{ .read = true });
        defer file.close();

        // TODO: Maybe make this an Arraylist???
        var str: [10240]u8 = undefined;
        const num_read = try file.readAll(&str);

        var parser = std.json.Parser.init(gpa, false);
        defer parser.deinit();

        var tree = try parser.parse(str[0..num_read]);
        defer tree.deinit();

        const log = blk: {
            var log = ArrayList(LogItem).init(gpa);

            var log_iter = tree.root.Object.get("log").?.Array.items;
            for (log_iter) |*entry| {
                const log_item = try LogItem.from_json_map(&entry.Object);
                try log.append(log_item);
            }

            break :blk log;
        };

        const webcash = blk: {
            var webcash = ArrayList(SecretWebcash).init(gpa);

            var webcash_iter = tree.root.Object.get("webcash").?.Array.items;
            for (webcash_iter) |entry| {
                const cash = try SecretWebcash.from_str(entry.String);
                try webcash.append(cash);
            }

            break :blk webcash;
        };

        // TODO:
        // const unconfirmed = tree.root.Object.get("unconfirmed").?.String;
        const unconfirmed = blk: {
            var unconfirmed = ArrayList(SecretWebcash).init(gpa);

            var unconfirmed_iter = tree.root.Object.get("unconfirmed").?.Array.items;
            for (unconfirmed_iter) |entry| {
                const cash = try SecretWebcash.from_str(entry.String);
                try unconfirmed.append(cash);
            }

            break :blk unconfirmed;
        };
        const master_secret = blk: {
            var secret: [32]u8 = undefined;

            const json_secret = tree.root.Object.get("master_secret").?.String;
            _ = try hexToBytes(&secret, json_secret);

            break :blk secret;
        };

        var legal_acks = blk: {
            var legal_acks = AutoHashMap(Legalese, bool).init(gpa);
            errdefer legal_acks.deinit();

            var legal_acks_itr = tree.root.Object.get("legalese").?.Object.iterator();
            while (legal_acks_itr.next()) |entry| {
                const legalese = try Legalese.from_str(entry.key_ptr.*);
                try legal_acks.put(legalese, entry.value_ptr.*.Bool);
            }

            break :blk legal_acks;
        };

        var wallet_depths = blk: {
            var wallet_depths = AutoHashMap(ChainCode, u32).init(gpa);
            errdefer wallet_depths.deinit();

            var wallet_depths_iter = tree.root.Object.get("walletdepths").?.Object.iterator();
            while (wallet_depths_iter.next()) |entry| {
                const chaincode = try ChainCode.from_str(entry.key_ptr.*);
                try wallet_depths.put(chaincode, @intCast(u32, entry.value_ptr.*.Integer));
            }

            break :blk wallet_depths;
        };

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

    // TODO:
    pub fn insert(self: *Wallet, webcash: []const u8) !void {
        // 1. Check legal agreements again?
        if (!self.check_legal_agreements()) {
            std.debug.print("User must acknowledge and agree to agreements first.\n", .{});
            return;
        }

        // 2. Deserialize the webcash and throw error if not legit.
        var webcash_der = try SecretWebcash.from_str(webcash);

        // 3. Create a new webcash object using the amount from deserialized webcash
        // 3.0 Generate new secret using the webcash wallet and passing a chaincode of RECEIVE?
        var secret_value: U256 = undefined;
        random.bytes(&secret_value);

        var new_webcash = SecretWebcash{
            .amount = webcash_der.amount,
            .secret = secret_value,
        };

        // 4. Save the deserialized webcash and new_webcash to the webcash_wallet as unconfirmed?
        try self.unconfirmed.append(webcash_der);
        try self.unconfirmed.append(new_webcash);

        try self.save(wallet_name);

        // 5. Create a request to send to the webcash server:
        // {webcashes: [str(webcash)], new_webcashes: [str(new_webcash)], "legalese": webcash_wallet["legalese"]}

        // 6. Send a HTTP request to the webcash_server

        // 7. Save the new webcash to the wallet
        //
        // 8. Remove unconfirmed webcash from the wallet
        //
        // 9. Add a log to the wallet
        try self.log.append(LogItem{
            .log_type = LogType.insert,
            .memo = "",
            .amount = @intCast(u64, webcash_der.amount),
            .input_webcash = "",
            .output_webcash = "",
        });

        // 10. Save the webcash wallet
        try self.save(wallet_name);
    }

    pub fn prompt_legal_acks(self: *Wallet) !void {
        if (self.check_legal_agreements()) {
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
                        try self.legal_acks.put(item, true);
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

    pub fn check_legal_agreements(self: Wallet) bool {
        for (Legalese.items) |item| {
            const ack = self.legal_acks.get(item) orelse return false;
            if (!ack) return false;
        }

        return true;
    }

    // TODO: Generate New Secret
    // - Omitting walletdepth=None as arg
    pub fn generate_new_secret(self: *Wallet, chain_code: ChainCode) !void {
        var tag: U256 = undefined;
        Sha256.hash("webcashwalletv1", &tag, .{});

        var double_tag: [64]u8 = undefined;
        mem.copy(u8, double_tag[0..32], &tag);
        mem.copy(u8, double_tag[32..], &tag);

        var new_secret = Sha256.init(.{});
        new_secret.update(&double_tag);
        new_secret.update(&self.master_secret);

        var chain_code_bytes = ArrayList(u8).init(self.gpa);
        defer chain_code_bytes.deinit();
        try chain_code_bytes.writer().writeIntBig(u64, @enumToInt(chain_code));

        new_secret.update(chain_code_bytes.items);

        var wallet_depth_bytes = ArrayList(u8).init(self.gpa);
        defer wallet_depth_bytes.deinit();

        const wallet_depth = self.wallet_depths.get(chain_code).?;
        std.debug.print("DEBUG: wallet depth {d}\n", .{wallet_depth});
        try wallet_depth_bytes.writer().writeIntBig(u64, wallet_depth);

        new_secret.update(wallet_depth_bytes.items);

        var hash_output: U256 = undefined;
        new_secret.final(&hash_output);
        std.debug.print("DEBUG: {x}\n", .{fmt.fmtSliceHexLower(&hash_output)});

        try self.wallet_depths.put(chain_code, wallet_depth + 1);
        try self.save(wallet_name);
    }
};

// TODO: This requires an existing wallet for this test to pass.
test "generate_new_secret" {
    var wallet = try Wallet.load(testing.allocator, "default_wallet.webcash");
    defer wallet.deinit();

    try wallet.generate_new_secret(ChainCode.receive);
}

test "create and load wallet" {
    // Generate a test wallet, insert some webcash and save to disk.
    var wallet = try Wallet.init(testing.allocator);
    defer wallet.deinit();

    // TODO: Use insert? (but need to avoid the rpc call).
    try wallet.webcash.append(.{ .amount = 10, .secret = [_]u8{0} ** 32 });
    try wallet.webcash.append(.{ .amount = 500, .secret = [_]u8{1} ** 32 });

    var expected_secret: [32]u8 = undefined;
    _ = try hexToBytes(&expected_secret, "ff6cfa803d9ef934cb503295902032c6b1976c0c7313d44b0ca7c6dce268777e");

    try wallet.webcash.append(.{ .amount = 700, .secret = expected_secret });

    try wallet.save("tmp-test-wallet");

    // Load the wallet and check the wallet can be serailized and deserialized.
    var loaded_wallet = try Wallet.load(testing.allocator, "tmp-test-wallet");
    defer loaded_wallet.deinit();

    try testing.expectEqualSlices(LogItem, wallet.log.items, loaded_wallet.log.items);

    // Check the webcash array was updated.
    try testing.expectEqual(loaded_wallet.webcash.items.len, 3);
    try testing.expectEqual(loaded_wallet.webcash.items[0].amount, 10);
    try testing.expectEqual(loaded_wallet.webcash.items[1].amount, 500);
    try testing.expectEqual(loaded_wallet.webcash.items[2].amount, 700);

    try testing.expectEqualSlices(
        u8,
        &loaded_wallet.webcash.items[0].secret,
        &([_]u8{0} ** 32),
    );
    try testing.expectEqualSlices(
        u8,
        &loaded_wallet.webcash.items[1].secret,
        &([_]u8{1} ** 32),
    );
    try testing.expectEqualSlices(
        u8,
        &loaded_wallet.webcash.items[2].secret,
        &expected_secret,
    );

    // Check the unconfirmed array was updated.
    // try testing.expectEqual(loaded_wallet.unconfirmed.items.len, 3);

    try testing.expectEqualSlices(SecretWebcash, wallet.unconfirmed.items, loaded_wallet.unconfirmed.items);
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

pub fn file_exists(file_name: []const u8) bool {
    var file = fs.cwd().openFile(file_name, .{}) catch {
        return false;
    };
    defer file.close();

    return true;
}

pub const SecretWebcash = struct {
    amount: u64,
    secret: U256,

    pub const Error = error{
        InvalidAmount,
        InvalidPublicOrSecret,
        InvalidSecret,
    };

    pub fn from_str(input: []const u8) !SecretWebcash {
        var iter = mem.split(input, ":");

        var amount_part = iter.next() orelse return Error.InvalidAmount;
        var public_or_secret = iter.next() orelse return Error.InvalidPublicOrSecret;
        var secret_part = iter.next() orelse return Error.InvalidSecret;

        var secret: [32]u8 = undefined;
        _ = try hexToBytes(&secret, secret_part);

        const amount = blk: {
            if (mem.startsWith(u8, amount_part, "e"))
                break :blk try fmt.parseInt(u64, amount_part[1..], 10);

            break :blk try fmt.parseInt(u64, amount_part, 10);
        };

        return SecretWebcash{
            .amount = amount,
            .secret = secret,
        };
    }

    pub fn to_str(self: @This(), gpa: *mem.Allocator) !ArrayList(u8) {
        var str = std.ArrayList(u8).init(gpa);
        try str.writer().print("e{}:secret:{}", .{
            self.amount,
            fmtSliceHexLower(&self.secret),
        });

        return str;
    }
};

test "se/deserialize SecretWebcash from str" {
    const input = "e1000:secret:ff6cfa803d9ef934cb503295902032c6b1976c0c7313d44b0ca7c6dce268777e";
    const secret_webcash = try SecretWebcash.from_str(input);

    try testing.expectEqual(secret_webcash.amount, 1000);

    var expected_secret: [32]u8 = undefined;
    _ = try hexToBytes(&expected_secret, "ff6cfa803d9ef934cb503295902032c6b1976c0c7313d44b0ca7c6dce268777e");
    try testing.expectEqualSlices(u8, &secret_webcash.secret, &expected_secret);

    var secret_webcash_str = try secret_webcash.to_str(testing.allocator);
    defer secret_webcash_str.deinit();

    try testing.expectEqualSlices(u8, secret_webcash_str.items, input);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    // TODO: Is there a better way to do this?
    var wallet = blk: {
        if (!file_exists(wallet_name)) {
            var wallet = try Wallet.init(&gpa.allocator);

            try wallet.prompt_legal_acks();
            try wallet.save(wallet_name);

            break :blk wallet;
        }

        break :blk try Wallet.load(&gpa.allocator, wallet_name);
    };
    defer wallet.deinit();

    const arguments = try args.parseForCurrentProcess(
        struct {
            // This declares long options for double hyphen
            help: bool = false,
            insert: ?[]const u8 = null,

            // This declares short-hand options for single hyphen
            pub const shorthands = .{
                .h = "help",
                .i = "insert",
            };
        },
        &gpa.allocator,
        .print,
    );
    defer arguments.deinit();

    // --help or -h
    if (arguments.options.help) {
        std.debug.print("Options:", .{});
        inline for (std.meta.fields(@TypeOf(arguments.options))) |fld| {
            std.debug.print("\t{s}\n", .{fld.name});
        }
    }

    // --insert or -i
    if (arguments.options.insert) |webcash_str| {
        try wallet.insert(webcash_str);
    }
}
