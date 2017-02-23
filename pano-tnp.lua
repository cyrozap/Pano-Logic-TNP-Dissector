-- Pano Logic Thin Network Protocol dissector for Wireshark
--
-- Copyright (C) 2017 Forest Crossman <cyrozap@gmail.com>
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, see <http://www.gnu.org/licenses/>.

-- Usage: wireshark -X lua_script:pano-tnp.lua

-- Create custom protocol.
p_tnp = Proto("tnp", "Pano Logic Thin Network Protocol")

-- Generic bit settings
local generic_bit_settings = {
    [0] = "Not set",
    [1] = "Set"
}

-- Endpoint 0 OpCodes
local ep0_opcodes = {
    [0x0] = "Configuration Read Request",
    [0x1] = "Configuration Write Request",
    [0x2] = "Configuration Read Return",
    [0x3] = "CSR Read Request",
    [0x4] = "CSR Write Request",
    [0x5] = "CSR Read Return",
    [0x6] = "Interrupt",
    [0x7] = "Error",
    [0x8] = "Announce",
}

-- TNP fields
p_tnp.fields.ver_id = ProtoField.uint8("tnp.ver_id", "Version/ID", base.HEX, nil)

p_tnp.fields.flags = ProtoField.uint8("tnp.flags", "Flags", base.HEX, nil)
p_tnp.fields.flags_syn = ProtoField.uint8("tnp.syn", "Syn", base.DEC, generic_bit_settings, 0x80)
p_tnp.fields.flags_ack = ProtoField.uint8("tnp.ack", "Ack", base.DEC, generic_bit_settings, 0x40)
p_tnp.fields.flags_nack = ProtoField.uint8("tnp.nack", "Nack", base.DEC, generic_bit_settings, 0x20)
p_tnp.fields.flags_reset = ProtoField.uint8("tnp.reset", "Reset", base.DEC, generic_bit_settings, 0x10)
p_tnp.fields.flags_oob = ProtoField.uint8("tnp.oob", "OOB", base.DEC, generic_bit_settings, 0x08)
p_tnp.fields.flags_ordered = ProtoField.uint8("tnp.ordered", "Ordered", base.DEC, generic_bit_settings, 0x04)
p_tnp.fields.flags_noack = ProtoField.uint8("tnp.noack", "NoAck", base.DEC, generic_bit_settings, 0x02)
p_tnp.fields.flags_reserved = ProtoField.uint8("tnp.reserved", "Reserved", base.DEC, generic_bit_settings, 0x01)

p_tnp.fields.seqno = ProtoField.uint16("tnp.seqno", "Sequence Number", base.DEC, nil, 0xfff0)

p_tnp.fields.ackseqno_orderid = ProtoField.uint16("tnp.ackseqno_orderid", "Ack Sequence Number/Order ID", base.DEC, nil, 0x0fff)

p_tnp.fields.security = ProtoField.bytes("tnp.security", "Security Data")

p_tnp.fields.payload = ProtoField.bytes("tnp.payload", "Payload")

-- Payload fields
p_tnp.fields.message = ProtoField.bytes("tnp.payload.message", "Payload Message")
p_tnp.fields.message_endpoint = ProtoField.uint16("tnp.payload.message.endpoint", "Endpoint", base.HEX, nil, 0xf800)
p_tnp.fields.message_length = ProtoField.uint16("tnp.payload.message.length", "Length", base.DEC, nil, 0x07ff)
p_tnp.fields.message_data = ProtoField.bytes("tnp.payload.message.data", "Data")

-- Endpoint 0 message fields
p_tnp.fields.ep0 = ProtoField.bytes("tnp.payload.message.data.ep0", "EP0 Message")
p_tnp.fields.ep0_opcode = ProtoField.uint8("tnp.payload.message.data.ep0.opcode", "OpCode", base.HEX, ep0_opcodes, 0xf0)
p_tnp.fields.ep0_length = ProtoField.uint8("tnp.payload.message.data.ep0.length", "Length", base.HEX, nil, 0x0f)
p_tnp.fields.ep0_address = ProtoField.uint24("tnp.payload.message.data.ep0.address", "Address", base.HEX)
p_tnp.fields.ep0_transaction_id = ProtoField.uint16("tnp.payload.message.data.ep0.transaction_id", "Transaction ID", base.HEX)
p_tnp.fields.ep0_data = ProtoField.bytes("tnp.payload.message.data.ep0.data", "Transaction Data")

-- Insert warning for undecoded leftover data.
local function warn_undecoded(tree, range)
    local item = tree:add(p_tnp.fields.unknown, range)
    item:add_expert_info(PI_UNDECODED, PI_WARN, "Leftover data")
end

-- Dissect Endpoint 0 message.
local function dissect_ep0_message(buffer, pinfo, tree)
    local message_tree = tree:add(p_tnp.fields.ep0, buffer)
    message_tree:add(p_tnp.fields.ep0_opcode, buffer(0, 1))
    message_tree:add(p_tnp.fields.ep0_length, buffer(0, 1))
    message_tree:add(p_tnp.fields.ep0_address, buffer(1, 3))
    message_tree:add(p_tnp.fields.ep0_transaction_id, buffer(4, 2))
    if (buffer:len() > 6) then
        message_tree:add(p_tnp.fields.ep0_data, buffer(6))
    end
end

-- Dissect TNP payload.
local function dissect_payload(buffer, pinfo, tree)
    local payload_tree = tree:add(p_tnp.fields.payload, buffer)
    -- The payload can contain multiple messages, so we need to keep
    -- parsing and looping until there aren't any left.
    local offset = 0
    while (true) do
        local endpoint = buffer(offset, 2):bitfield(0, 5)
        local data_length = buffer(offset, 2):bitfield(5, 11)
        local data = buffer(offset+2, data_length)

        local message_tree = payload_tree:add(p_tnp.fields.message, buffer(offset, 2+data_length))
        message_tree:add(p_tnp.fields.message_endpoint, buffer(offset, 2))
        message_tree:add(p_tnp.fields.message_length, buffer(offset, 2))
        local data_tree = message_tree:add(p_tnp.fields.message_data, data)

        if (endpoint == 0) then
            dissect_ep0_message(data, pinfo, data_tree)
        end

        offset = offset+2+data_length
        if (offset == buffer:len()) then
            break
        end
    end
end

-- Main TNP dissector function.
function p_tnp.dissector(buffer, pinfo, tree)
    local tnp_tree = tree:add(p_tnp, buffer(), "TNP")

    tnp_tree:add(p_tnp.fields.ver_id, buffer(0,1))

    local flags = buffer(1,1)
    local flags_tree = tnp_tree:add(p_tnp.fields.flags, flags)
    flags_tree:add(p_tnp.fields.flags_syn, flags)
    flags_tree:add(p_tnp.fields.flags_ack, flags)
    flags_tree:add(p_tnp.fields.flags_nack, flags)
    flags_tree:add(p_tnp.fields.flags_reset, flags)
    flags_tree:add(p_tnp.fields.flags_oob, flags)
    flags_tree:add(p_tnp.fields.flags_ordered, flags)
    flags_tree:add(p_tnp.fields.flags_noack, flags)
    flags_tree:add(p_tnp.fields.flags_reserved, flags)

    tnp_tree:add(p_tnp.fields.seqno, buffer(2,2))

    tnp_tree:add(p_tnp.fields.ackseqno_orderid, buffer(3,2))

    tnp_tree:add(p_tnp.fields.security, buffer(5,3))

    if (buffer:len() > 8) then
        dissect_payload(buffer(8), pinfo, tnp_tree)
    end
end

function p_tnp.init()
    local udp_port_dissectors = DissectorTable.get("udp.port")
    udp_port_dissectors:add(8320, p_tnp)
    udp_port_dissectors:add(8321, p_tnp)
end
