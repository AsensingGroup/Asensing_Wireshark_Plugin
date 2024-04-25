-- Copyright (c) 2022-2024, Asensing Group
--
-- Asensing A2 LiDAR protocol plugin for Wireshark
--
-- Change Logs:
-- Date           Author       Notes
-- 2022-06-30     luhuadong    the first Version
-- 2023-09-12     luhuadong    update lidar protocol
-- 2024-04-25     luhuadong    add 96S mode


-- Declare our protocol
lidar_proto = Proto("A2", "Asensing A2 LiDAR Protocol")

-- Header fields
Sob = ProtoField.none ("asensing.Sob", "Sob", base.HEX)
HeaderLen = ProtoField.uint16 ("asensing.HeaderLen", "HeaderLen", base.DEC)
PayloadLen = ProtoField.uint16 ("asensing.PayloadLen", "PayloadLen", base.DEC)
LidarType = ProtoField.uint8 ("asensing.LidarType", "LidarType", base.HEX)
LidarInfo = ProtoField.uint8 ("asensing.LidarInfo", "LidarInfo", base.HEX)
Version = ProtoField.uint8 ("asensing.Version", "Version", base.HEX)
LiDARFlag1 = ProtoField.uint8 ("asensing.LiDARFlag1", "LidarFlag1", base.HEX)
LiDARFlag2 = ProtoField.uint8 ("asensing.LiDARFlag2", "LidarFlag2", base.HEX)
AngleResolutionV = ProtoField.uint8 ("asensing.AngleResolutionV", "AngleResolutionV", base.DEC)
AngleResolutionH = ProtoField.uint8 ("asensing.AngleResolutionH", "AngleResolutionH", base.DEC)

ColumnOffset = ProtoField.uint16 ("asensing.ColumnOffset", "ColumnOffset", base.DEC)
ChannelNum = ProtoField.uint16 ("asensing.ChannelNum", "ChannelNum", base.DEC)
SlotNum = ProtoField.uint16 ("asensing.SlotNum", "SlotNum", base.DEC)
BlockNum = ProtoField.uint8 ("asensing.BlockNum", "BlockNum", base.DEC)

FrameID = ProtoField.uint16 ("asensing.FrameID", "FrameID", base.DEC)
PktSeq = ProtoField.uint16 ("asensing.PktSeq", "PktSeq", base.DEC)

utc_time0 = ProtoField.uint8 ("asensing.utc_time0", "UTCTime0", base.DEC)
utc_time1 = ProtoField.uint8 ("asensing.utc_time1", "UTCTime1", base.DEC)
utc_time2 = ProtoField.uint8 ("asensing.utc_time2", "UTCTime2", base.DEC)
utc_time3 = ProtoField.uint8 ("asensing.utc_time3", "UTCTime3", base.DEC)
utc_time4 = ProtoField.uint8 ("asensing.utc_time4", "UTCTime4", base.DEC)
utc_time5 = ProtoField.uint8 ("asensing.utc_time5", "UTCTime5", base.DEC)
time_stamp = ProtoField.uint32 ("asensing.time_stamp", "Timestamp", base.DEC)

HeaderReserve = ProtoField.uint16 ("asensing.HeaderReserve", "HeaderReserve", base.DEC)
DataID = ProtoField.uint16 ("asensing.DataID", "DataID", base.DEC)
DataValue = ProtoField.uint32 ("asensing.DataValue", "DataValue", base.DEC)


ele_angle_offset = ProtoField.int8 ("asensing.ele_angle_offset", "ElevationAngleOffset", base.DEC)
payload_flag = ProtoField.uint8 ("asensing.payload_flag", "PayloadFlag", base.DEC)

-- Block fields
distance = ProtoField.uint16 ("asensing.block.unit.distance", "Distance", base.DEC)
-- azimuth = ProtoField.uint16 ("asensing.block.unit.azimuth", "Azimuth", base.DEC)
-- elevation = ProtoField.uint16 ("asensing.block.unit.elevation", "Elevation", base.DEC)
intensity = ProtoField.uint8 ("asensing.block.unit.intensity", "Intensity", base.DEC)
confidence = ProtoField.uint8 ("asensing.block.unit.confidence", "Confidence", base.DEC)


lidar_proto.fields = {
    -- Header
    Sob, HeaderLen, PayloadLen, LidarType, LidarInfo, Version, LiDARFlag1, LiDARFlag2,
    AngleResolutionV, AngleResolutionH, ColumnOffset, ChannelNum, SlotNum, BlockNum,
    FrameID, PktSeq, utc_time0, utc_time1, utc_time2, utc_time3, utc_time4, utc_time5,
    time_stamp, HeaderReserve, DataID, DataValue,
    -- Block
    distance, intensity, confidence
}

-- Create a function to dissect it
function lidar_proto.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = lidar_proto.name;
    local subtree = tree:add(lidar_proto, buffer(), "Asensing A2 LiDAR packet data")

    local curr = 0

    local headerSize = 42

    local blockPerPacket = 3

    local nbLaser = 96
    local laserSize = 4
    local nbEcho = 1
    local blockSize =  6 + (nbLaser * laserSize * nbEcho)

    local tailSize = 4

    -- Packet Header --
    local header_subtree = subtree:add_le(buffer(curr, headerSize), "Header")

    header_subtree:add_le(Sob, buffer(curr, 2))
    curr = curr + 2

    header_subtree:add_le(HeaderLen, buffer(curr, 2))
    curr = curr + 2

    header_subtree:add_le(PayloadLen, buffer(curr, 2))
    curr = curr + 2

    header_subtree:add(LidarType, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add(LidarInfo, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add(Version, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add(LiDARFlag1, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add(LiDARFlag2, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add(AngleResolutionV, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add(AngleResolutionH, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add_le(ColumnOffset, buffer(curr, 2))
    curr = curr + 2

    header_subtree:add_le(ChannelNum, buffer(curr, 2))
    curr = curr + 2

    header_subtree:add_le(SlotNum, buffer(curr, 2))
    curr = curr + 2

    header_subtree:add(BlockNum, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add_le(FrameID, buffer(curr, 2))
    curr = curr + 2

    header_subtree:add_le(PktSeq, buffer(curr, 2))
    curr = curr + 2

    header_subtree:add(utc_time0, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add(utc_time1, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add(utc_time2, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add(utc_time3, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add(utc_time4, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add(utc_time5, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add_le(time_stamp, buffer(curr, 4))
    curr = curr + 4

    header_subtree:add_le(HeaderReserve, buffer(curr, 2))
    curr = curr + 2

    header_subtree:add_le(DataID, buffer(curr, 2))
    curr = curr + 2

    header_subtree:add_le(DataValue, buffer(curr, 2))
    curr = curr + 4

    ---- bock Return ----
    local size = blockPerPacket * blockSize
    local blockreturns = subtree:add(buffer(curr, size), "Blocks")

    for i=0, blockPerPacket-1
    do
        local block_subtree = blockreturns:add(buffer(curr, blockSize), "Block Return : " ..i)

        local elevationAngleOffset = buffer(curr, 2):uint()
        block_subtree:add_le(buffer(curr, 2), "ElevationAngleOffset : " .. elevationAngleOffset)
        curr = curr + 2

        local azimuth = buffer(curr, 2):uint()
        block_subtree:add_le(buffer(curr, 2), "Azimuth : " .. azimuth)
        curr = curr + 2

        local fineAzimuth = buffer(curr, 1):uint()
        block_subtree:add_le(buffer(curr, 1), "FineAzimuth : " .. fineAzimuth)
        curr = curr + 1

        local payloadFlag = buffer(curr, 1):uint()
        block_subtree:add_le(buffer(curr, 1), "PayloadFlag : " .. payloadFlag)
        curr = curr + 1
        
        local all_laser_subtree = block_subtree:add(buffer(curr, laserSize * nbLaser * nbEcho), "All Lasers Return")

        for j=0, nbLaser-1
        do
            local laser_subtree = all_laser_subtree:add(buffer(curr, laserSize), "Laser Return : " ..j)

            for k=0, nbEcho-1
            do
                local echo_subtree = laser_subtree:add(buffer(curr, laserSize), "Echo : " ..k)
            
                echo_subtree:add_le(distance, buffer(curr, 2))
                curr = curr + 2

                echo_subtree:add_le(intensity, buffer(curr, 1))
                curr = curr + 1

                echo_subtree:add_le(confidence, buffer(curr, 1))
                curr = curr + 1
            end

        end

    end


    -- Tail --
    local tail_subtree = subtree:add(buffer(curr, tailSize), "Tail")

    local CRC = buffer(curr, 4):uint()
    tail_subtree:add_le(buffer(curr, 4), "CRC : " .. CRC)
    curr = curr + 4
    
    --[[
    for n=0, 16
    do
        local functionSafety_subtree = tail_subtree:add(buffer(curr,1),"functionSafety subtree : " ..n)

        local functionSafety = buffer(curr,1):uint()
        functionSafety_subtree:add(buffer(curr,1),"functionSafety  : " .. functionSafety)
        curr = curr + 1
    end
    --]]

end


-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 51180
udp_table:add(51180, lidar_proto)
