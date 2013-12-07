# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'macho/version'

Gem::Specification.new do |spec|
  spec.name          = "macho"
  spec.version       = Macho::VERSION
  spec.authors       = ["Jon Parise", "James McMahon", "Jiwei Wu"]
  spec.email         = ["jmcmahon@skillz.com"]
  spec.description   = %q{A small Ruby library for parsing Mach-O binaries}
  spec.summary       = %q{Mach-O binary library}
  spec.homepage      = "https://github.com/skillz/macho"
  spec.license       = "MIT"

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.3"
  spec.add_development_dependency "rake"
end
