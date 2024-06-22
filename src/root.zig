/// DoH or DNS over HTTPS is a way to more securely resolve an ip address for a given DNS host name
/// see also https://datatracker.ietf.org/doc/html/draft-bortzmeyer-dns-json
const std = @import("std");
const testing = std.testing;

pub const Question = struct {
    name: []const u8,
    type: usize,
};

pub const Answer = struct {
    name: []const u8,
    type: usize,
    TTL: usize,
    data: []const u8,

    pub fn recordType(self: @This()) RecordType {
        return RecordType.fromInt(self.type);
    }
};

pub const Response = struct {
    Status: usize,
    TC: bool,
    RD: bool,
    RA: bool,
    AD: bool,
    CD: bool,
    Question: []const Question,
    Answer: []const Answer,
};

/// https://en.wikipedia.org/wiki/List_of_DNS_record_types
pub const RecordType = enum(usize) {
    a = 1,
    ns = 2,
    cname = 5,
    soa = 6,
    txt = 16,
    key = 25,
    aaaa = 28,
    srv = 33,
    dname = 39,
    ds = 43,
    ipseckey = 45,
    dnskey = 48,
    dhcid = 49,
    nsec3param = 51,
    openpgpkey = 61,
    caa = 257,
    // todo: fill in others as needed
    pub fn string(self: @This()) []const u8 {
        return @tagName(self);
    }
    pub fn fromInt(i: usize) RecordType {
        return @enumFromInt(i);
    }
};
pub const ResolveOptions = struct {
    type: RecordType = .a,
    cd: bool = false,
    do: bool = false,
};

pub const Provider = enum {
    /// Google provider
    /// https://developers.google.com/speed/public-dns/docs/doh/json
    google,
    /// Cloudflare provider
    /// https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/
    cloudflare,

    fn endpoint(self: @This()) []const u8 {
        return switch (self) {
            .google => "https://dns.google/resolve",
            .cloudflare => "https://cloudflare-dns.com/dns-query",
        };
    }
};

pub const HttpClient = union(enum) {
    /// use a default http client
    default: void,
    // provide your own http client
    provided: std.http.Client,
};

pub const ClientOptions = struct {
    client: HttpClient = .default,
    provider: Provider = .google,
};

pub fn Owned(comptime T: type) type {
    return struct {
        value: T,
        arena: *std.heap.ArenaAllocator,
        pub fn deinit(self: @This()) void {
            const allocator = self.arena.child_allocator;
            self.arena.deinit();
            allocator.destroy(self.arena);
        }
    };
}

pub const Client = struct {
    allocator: std.mem.Allocator,
    options: ClientOptions,
    client: std.http.Client,
    pub fn init(allocator: std.mem.Allocator, options: ClientOptions) @This() {
        return .{
            .allocator = allocator,
            .options = options,
            .client = switch (options.client) {
                .default => .{ .allocator = allocator },
                .provided => |p| p,
            },
        };
    }

    pub fn deinit(self: *@This()) void {
        self.client.deinit();
    }

    pub fn resolve(self: *@This(), name: []const u8, options: ResolveOptions) !Owned(Response) {
        const url = try std.fmt.allocPrint(self.allocator, "{s}?name={s}&type={s}&cd={any}&do={any}", .{ self.options.provider.endpoint(), name, @tagName(options.type), options.cd, options.do });
        defer self.allocator.free(url);
        var resp = std.ArrayList(u8).init(self.allocator);

        const res = try self.client.fetch(.{
            .location = .{ .url = url },
            .extra_headers = &.{
                .{
                    .name = "Accept",
                    .value = "application/dns-json",
                },
            },
            .response_storage = .{ .dynamic = &resp },
        });
        if (res.status.class() != .success) {
            return error.RequestFailed;
        }
        const bytes = try resp.toOwnedSlice();
        defer self.allocator.free(bytes);
        const parsed = try std.json.parseFromSlice(Response, self.allocator, bytes, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
        return Owned(Response){ .value = parsed.value, .arena = parsed.arena };
    }
};

test Client {
    const allocator = std.testing.allocator;
    var client = Client.init(allocator, .{});
    defer client.deinit();
    var resp = try client.resolve("_mongodb._tcp.cluster0.sm7ifrp.mongodb.net", .{ .type = .srv });
    defer resp.deinit();
    //std.debug.print("ans {any}", .{resp.value});
    for (resp.value.Answer) |ans| {
        std.debug.print("ans {any} {s} {s}\n", .{ ans.recordType(), ans.name, ans.data });
    }
}
