const std = @import("std");
const stream_table = @import("runtime/stream_table.zig");

test "StreamTable put get fetchRemove and generation bump" {
    try stream_table.runStreamTableUnitTests();
}
