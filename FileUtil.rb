#  Copyright (C) 2021, 2022 hidenorly
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "./StrUtil"

class FileUtil
	def self.ensureDirectory(path)
		paths = path.split("/")

		path = ""
		begin
			paths.each do |aPath|
				if !path.empty? then
					path += "/"+aPath
				else
					path = aPath
				end
				Dir.mkdir(path) if !Dir.exist?(path)
			end
		rescue => ex
		end
	end

	def self.removeDirectoryIfNoFile(path)
		found = false
		begin
			Dir.foreach( path ) do |aPath|
				next if aPath == '.' or aPath == '..'
				found = true
				break
			end
			FileUtils.rm_rf(path) if !found
		rescue => ex
		end
	end

	def self.cleanupDirectory(path, recursive=false, force=false)
		if recursive && force then
			FileUtils.rm_rf(path)
		elsif recursive then
			FileUtils.rm_r(path)
		elsif force then
			FileUtils.rm_f(path)
		else
			FileUtils.rmdir(path)
		end

		ensureDirectory(path)
	end

	def self.iteratePath(path, matchKey, pathes, recursive, dirOnly)
		begin
			Dir.foreach( path ) do |aPath|
				next if aPath == '.' or aPath == '..'

				fullPath = path.sub(/\/+$/,"") + "/" + aPath
				if FileTest.directory?(fullPath) then
					if dirOnly then
						if matchKey==nil || ( aPath.match(matchKey)!=nil ) then 
							pathes.push( fullPath )
						end
					end
					if recursive then
						iteratePath( fullPath, matchKey, pathes, recursive, dirOnly )
					end
				else
					if !dirOnly then
						if matchKey==nil || ( aPath.match(matchKey)!=nil ) then 
							pathes.push( fullPath )
						end
					end
				end
			end
		rescue => ex
		end
	end

	def self.getFilenameFromPath(path)
		pos = path.rindex("/")
		path = pos ? path.slice(pos+1, path.length-pos) : path
		return path
	end

	def self.getFilenameFromPathWithoutExt(path)
		path = getFilenameFromPath(path)
		pos = path.to_s.rindex(".")
		path = pos ? path.slice(0, pos) : path
		return path
	end

	def self.getDirectoryFromPath(path)
		pos = path.rindex("/")
		path = pos ? path.slice(0, pos) : path
		while( path.end_with?("/") ) do
			path = path.slice( 0, path.length-1 )
		end
		return path
	end

	# get regexp matched file list
	def self.getRegExpFilteredFiles(basePath, fileFilter)
		result=[]
		iteratePath(basePath, fileFilter, result, true, false)

		return result
	end

	def self.writeFile(path, body)
		if path then
			fileWriter = File.open(path, "w")
			if fileWriter then
				if body.kind_of?(Array) then
					body.each do |aLine|
						fileWriter.puts aLine
					end
				else
					fileWriter.puts body
				end
				fileWriter.close
			end
		end
	end

	def self.readFile(path)
		result = nil

		if path && FileTest.exist?(path) then
			fileReader = File.open(path)
			if fileReader then
				buf = fileReader.read
				result = StrUtil.ensureUtf8(buf) if buf.valid_encoding?
				fileReader.close
			end
		end

		return result
	end

	def self.readFileAsArray(path)
		result = []

		if path && FileTest.exist?(path) then
			fileReader = File.open(path)
			if fileReader then
				while !fileReader.eof
					result << StrUtil.ensureUtf8(fileReader.readline).strip
				end
				fileReader.close
			end
		end

		return result
	end

	def self.appendLineToFile(path, line)
		open(path, "a") do |f|
			f.puts line
		end
	end
end

class Stream
	def initialize
	end

	def eof?
		return true
	end

	def readline
		return nil
	end

	def each_line
		return [].each
	end

	def each
		return each_line
	end

	def readlines
		return []
	end
end

class ArrayStream < Stream
	def initialize(dataArray)
		@dataArray = dataArray.to_a
		@nPos = 0
	end

	def eof?
		return @nPos>=(@dataArray.length)
	end

	def readline
		result = nil
		if !eof?() then
			result = @dataArray[@nPos]
			@nPos = @nPos + 1
		end
		return result
	end

	def each_line
		return @dataArray.each
	end

	def readlines
		return @dataArray
	end
end

class FileStream < Stream
	def initialize(path)
		if File.exist?(path) then
			@io = File.open(path)
		else
			@io = nil
		end
	end

	def eof?
		return @io ? @io.eof? : true
	end

	def readline
		return @io ? @io.readline : nil
	end

	def each_line
		return @io ? @io.each_line : [].each
	end

	def readlines
		return @io ? @io.readlines : []
	end
end
