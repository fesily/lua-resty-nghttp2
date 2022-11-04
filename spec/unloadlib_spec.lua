describe('unload', function()
    require 'resty.nghttp2'
    package.loaded['resty.nghttp2'] = nil
    collectgarbage('collect')
end)
