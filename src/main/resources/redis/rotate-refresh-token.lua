-- All key types and arguments are checked before the first write. Lua isolates
-- this transition; Redis does not roll back writes after a runtime script error.
local types = {'string', 'string', 'string', 'string', 'set', 'string', 'string'}
for i, expected in ipairs(types) do
    local actual = redis.call('TYPE', KEYS[i]).ok
    if actual ~= 'none' and actual ~= expected then
        return redis.error_reply('Refresh token rotation encountered an invalid key type')
    end
end

local ttl = tonumber(ARGV[6])
if not ttl or ttl <= 0 or ttl ~= math.floor(ttl) then
    return redis.error_reply('Refresh token rotation requires a positive TTL')
end

local version = redis.call('GET', KEYS[6]) or '0'
if version ~= ARGV[7] or redis.call('EXISTS', KEYS[7]) ~= 0
        or redis.call('GET', KEYS[1]) ~= ARGV[1] then
    return 0
end

local oldJson = redis.call('GET', KEYS[2])
if not oldJson then return 0 end
local decoded, meta = pcall(cjson.decode, oldJson)
if not decoded or type(meta) ~= 'table' or type(meta.status) ~= 'string'
        or string.lower(meta.status) ~= 'active' or meta.userId ~= tonumber(ARGV[8]) then
    return 0
end
local family = meta.familyId
if family == nil or family == cjson.null then family = '' end
if family ~= ARGV[9] then return 0 end

if redis.call('EXISTS', KEYS[3], KEYS[4]) ~= 0 then
    return redis.error_reply('Refresh token successor already exists')
end

redis.call('SET', KEYS[3], ARGV[2], 'EX', ARGV[6])
redis.call('SET', KEYS[4], ARGV[5], 'EX', ARGV[6])
redis.call('SADD', KEYS[5], ARGV[4])
redis.call('DEL', KEYS[1], KEYS[2])
redis.call('SREM', KEYS[5], ARGV[3])
return 1
