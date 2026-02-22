Pod::Spec.new do |spec|
  spec.name         = 'GTOS'
  spec.version      = '{{.Version}}'
  spec.license      = { :type => 'GNU Lesser General Public License, Version 3.0' }
  spec.homepage     = 'https://github.com/tos-network/gtos'
  spec.authors      = { {{range .Contributors}}
		'{{.Name}}' => '{{.Email}}',{{end}}
	}
  spec.summary      = 'iOS TOS Client'
  spec.source       = { :git => 'https://github.com/tos-network/gtos.git', :commit => '{{.Commit}}' }

	spec.platform = :ios
  spec.ios.deployment_target  = '9.0'
	spec.ios.vendored_frameworks = 'Frameworks/GTOS.framework'

	spec.prepare_command = <<-CMD
    curl https://gtosstore.blob.core.windows.net/builds/{{.Archive}}.tar.gz | tar -xvz
    mkdir Frameworks
    mv {{.Archive}}/GTOS.framework Frameworks
    rm -rf {{.Archive}}
  CMD
end
