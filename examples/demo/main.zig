const std = @import("std");
const doh = @import("doh");

pub fn main() !void {
    var args = std.process.args();
    _ = args.next();

    const name = if (args.next()) |next| next else "api.github.com";

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // create a client using default provider, google. you can also use cloudflare, or a custom provider endpoint. this endpoint must support TLS 1.3
    var client = doh.Client.init(allocator, .{ .provider = .quad9 });
    defer client.deinit();

    // resolve a dns name

    var resp = try client.resolve(name, .{ .type = .A });
    defer resp.deinit();

    // inspect the answer
    for (resp.value.Answer) |answer| {
        std.debug.print("type: {s} name: {s} data: {s}\n", .{ @tagName(answer.recordType()), answer.name, answer.data });
    }
}
