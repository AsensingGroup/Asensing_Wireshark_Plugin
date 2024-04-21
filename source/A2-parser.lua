-- Copyright (c) 2022-2024, Asensing Group
--
-- Asensing A2 LiDAR protocol plugin for Wireshark
--
-- Change Logs:
-- Date           Author       Notes
-- 2022-06-30     luhuadong    the first version
-- 2023-09-12     luhuadong    update lidar protocol


-- Declare our protocol
lidar_proto = Proto("A2","Asensing A2 LiDAR Protocol")

-- Header fields
sob = ProtoField.none ("asensing.sob", "Sob", base.HEX)
lidar_type = ProtoField.uint8 ("asensing.lidar_type", "LidarType", base.HEX)
lidar_info = ProtoField.uint8 ("asensing.lidar_info", "LidarInfo", base.HEX)
version = ProtoField.uint8 ("asensing.version", "Version", base.HEX)
block_num = ProtoField.uint8 ("asensing.block_num", "BlockNum", base.DEC)
channel_num = ProtoField.uint16 ("asensing.channel_num", "ChannelNum", base.DEC)
lidar_flag1 = ProtoField.uint8 ("asensing.lidar_flag1", "LidarFlag1", base.HEX)
lidar_flag2 = ProtoField.uint8 ("asensing.lidar_flag2", "LidarFlag2", base.HEX)
point_num = ProtoField.uint32 ("asensing.point_num", "PointNum", base.DEC)
pkg_len = ProtoField.uint16 ("asensing.pkglen", "PkgLen", base.DEC)
frame_id = ProtoField.uint16 ("asensing.frameid", "FrameID", base.DEC)
seq_num = ProtoField.uint16 ("asensing.seqnum", "SeqNum", base.DEC)

utc_time0 = ProtoField.uint8 ("asensing.utc_time0", "UTCTime0", base.DEC)
utc_time1 = ProtoField.uint8 ("asensing.utc_time1", "UTCTime1", base.DEC)
utc_time2 = ProtoField.uint8 ("asensing.utc_time2", "UTCTime2", base.DEC)
utc_time3 = ProtoField.uint8 ("asensing.utc_time3", "UTCTime3", base.DEC)
utc_time4 = ProtoField.uint8 ("asensing.utc_time4", "UTCTime4", base.DEC)
utc_time5 = ProtoField.uint8 ("asensing.utc_time5", "UTCTime5", base.DEC)
time_stamp = ProtoField.uint32 ("asensing.time_stamp", "Timestamp", base.DEC)

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
    sob, lidar_type, lidar_info, version, block_num, channel_num, lidar_flag1, 
    lidar_flag2, point_num, pkg_len, frame_id, seq_num, utc_time0, utc_time1, 
    utc_time2, utc_time3, utc_time4, utc_time5, time_stamp, ele_angle_offset, 
    payload_flag, 
    -- Block
    distance, intensity, confidence
}

-- Create a function to dissect it
function lidar_proto.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end
    
    pinfo.cols.protocol = lidar_proto.name;
    local subtree = tree:add(lidar_proto, buffer(),"Asensing A2 LiDAR packet data")

    local curr = 0

    local headerSize = 32

    local blockPerPacket = 1
    
    local nbLaser = 96
    local laserSize = 4
    local nbEcho = 2
    local blockSize =  2 + 2 + (nbLaser * laserSize * nbEcho)
    
    local tailSize = 8

    -- Packet Header --
    local header_subtree = subtree:add_le(buffer(curr, headerSize), "Header")

    header_subtree:add_le(sob, buffer(curr, 2))
    curr = curr + 2

    header_subtree:add(lidar_type, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add(lidar_info, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add(version, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add(block_num, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add_le(channel_num, buffer(curr, 2))
    curr = curr + 2

    header_subtree:add(lidar_flag1, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add(lidar_flag2, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add_le(point_num, buffer(curr, 4))
    curr = curr + 4

    header_subtree:add_le(pkg_len, buffer(curr, 2))
    curr = curr + 2

    header_subtree:add_le(frame_id, buffer(curr, 2))
    curr = curr + 2

    header_subtree:add_le(seq_num, buffer(curr, 2))
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

    header_subtree:add(ele_angle_offset, buffer(curr, 1))
    curr = curr + 1

    header_subtree:add(payload_flag, buffer(curr, 1))
    curr = curr + 1

    ---- bock Return ----
    local size = blockPerPacket * blockSize
    local blockreturns = subtree:add(buffer(curr, size), "Blocks")

    for i=0, blockPerPacket-1
    do
        local block_subtree = blockreturns:add(buffer(curr,blockSize), "Block Return : " ..i)

        local timeOffSet = buffer(curr, 2):uint()
        block_subtree:add_le(buffer(curr, 2), "timeOffSet : " .. timeOffSet)
        curr = curr + 2

        local azimuth = buffer(curr, 2):uint()
        block_subtree:add_le(buffer(curr, 2), "Azimuth : " .. azimuth)
        curr = curr + 2
        
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
    tail_subtree:add_le(buffer(curr,4), "CRC : " .. CRC)
    curr = curr + 4

    local tail_reserved = buffer(curr, 4):uint()
    tail_subtree:add_le(buffer(curr, 4), "Reserved : " .. tail_reserved)
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
