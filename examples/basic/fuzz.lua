local aflua = require "aflua"

aflua.init()
aflua.coverage_hook(true)
aflua.run(function(buf)
    if #buf < 4 or #buf > 8 then
        return aflua.skip()
    end

    -- error if the buf starts with abab
    if string.byte(buf, 1, 1) == string.byte('a') then
        if string.byte(buf, 2, 2) == string.byte('b')  then
            if string.byte(buf, 3, 3) == string.byte('a')  then
                if string.byte(buf, 4, 4) == string.byte('b') then
                    error('starts with abab')
                end
            end
        end
    end
end)