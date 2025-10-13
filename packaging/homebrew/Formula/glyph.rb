# frozen_string_literal: true

class Glyph < Formula
  desc "Automation toolkit for orchestrating red-team and detection workflows"
  homepage "https://github.com/RowanDark/Glyph"
  url "https://github.com/RowanDark/Glyph/archive/6cdf809882689869dfb340dc2d68c709675443b6.tar.gz"
  version "0.0.0+dev"
  sha256 "d5558cd419c8d46bdc958064cb97f963d1ea793866414c025906ec15033512ed"
  license "Apache-2.0"

  depends_on "go" => :build

  def install
    ldflags = %w[
      -s -w
    ]
    system "go", "build", *std_go_args(output: bin/"glyphctl", ldflags: ldflags.join(" ")), "./cmd/glyphctl"
  end

  test do
    assert_match "glyphctl", shell_output("#{bin}/glyphctl --help")
  end
end
