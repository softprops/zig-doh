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

/// A response to a resolve request
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

/// An enumeration of dns record types
/// https://en.wikipedia.org/wiki/List_of_DNS_record_types
pub const RecordType = enum(usize) {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    HINFO = 13,
    MX = 15,
    TXT = 16,
    KEY = 25,
    AAAA = 28,
    SRV = 33,
    DNAME = 39,
    DS = 43,
    IPSECKEY = 45,
    DNSKEY = 48,
    DHCID = 49,
    NSEC3PARAM = 51,
    OPENPGPKEY = 61,
    HTTPS = 65,
    ANY = 255,
    CAA = 257,
    // todo: fill in others as needed
    pub fn toString(self: @This()) []const u8 {
        return @tagName(self);
    }
    pub fn fromInt(i: usize) RecordType {
        //std.debug.print("resolving int {d}\n", .{i});
        return @enumFromInt(i);
    }
    pub fn toInt(self: @This()) usize {
        return @intFromEnum(self);
    }
};

/// a collection of options for resolving a dns name
pub const ResolveOptions = struct {
    /// Record type, defaults to "ANY"
    type: RecordType = .ANY,
    /// The CD (Checking Disabled) flag, defaults to false
    cd: bool = false,
    /// The DO (DNSSEC OK) flag, defaults to false
    do: bool = false,
};

pub const Provider = union(enum) {
    /// Google provider
    ///
    /// see also https://developers.google.com/speed/public-dns/docs/doh/json
    google: void,
    /// Cloudflare provider
    ///
    /// see also https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/
    cloudflare: void,
    /// a custom user-provided https endpoint
    custom: []const u8,

    fn endpoint(self: @This()) []const u8 {
        return switch (self) {
            .google => "https://dns.google/resolve",
            .cloudflare => "https://cloudflare-dns.com/dns-query",
            .custom => |e| e,
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

/// A type which carries ownership over the memory value is attached to
/// call deinit() after using the value to free it
pub fn Owned(comptime T: type) type {
    return struct {
        value: T,
        arena: *std.heap.ArenaAllocator,
        /// free's memory associated with value
        pub fn deinit(self: @This()) void {
            const allocator = self.arena.child_allocator;
            self.arena.deinit();
            allocator.destroy(self.arena);
        }
    };
}

/// A DoH client
pub const Client = struct {
    allocator: std.mem.Allocator,
    options: ClientOptions,
    client: std.http.Client,
    /// constructs a new Client with a set of options
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

    /// free's allocated resources
    pub fn deinit(self: *@This()) void {
        self.client.deinit();
    }

    /// resolves a dns name with a provided set of options. these default to resolving the name for any type of record
    /// for specific cases you will want to request a specific type of record
    pub fn resolve(self: *@This(), name: []const u8, options: ResolveOptions) !Owned(Response) {
        const url = try std.fmt.allocPrint(self.allocator, "{s}?name={s}&type={d}&cd={any}&do={any}", .{ self.options.provider.endpoint(), name, options.type.toInt(), options.cd, options.do });
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
    var resp = try client.resolve("google.com", .{});
    defer resp.deinit();
    for (resp.value.Answer) |ans| {
        std.debug.print("ans {s} {s} {s}\n", .{ ans.recordType().toString(), ans.name, ans.data });
    }
}
