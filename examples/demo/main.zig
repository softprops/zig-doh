const std = @import("std");
const doh = @import("doh");

pub fn main() !void {
    var args = std.process.args();
    _ = args.next();

    const name = if (args.next()) |next| next else "api.github.com";

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // create a client
    var client = doh.Client.init(allocator, .{});
    defer client.deinit();

    // resolve a dns name

    var resp = try client.resolve(name, .{});
    defer resp.deinit();

    // inspect the answer
    for (resp.value.Answer) |answer| {
        std.debug.print("type: {s} name: {s} data: {s}\n", .{ answer.recordType().toString(), answer.name, answer.data });
    }
}
