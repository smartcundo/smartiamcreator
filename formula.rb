require 'formula'

class IAMCredentialsCreator < Formula
  homepage 'https://github.com/smartcundo/smartiamcreator'
  url 'https://github.com/smartcundo/smartiamcreator/archive/0.0.1.tar.gz'
  sha1 '0a25f5a5e14ff373345789a1653382f02f437ae0'

  def install
    bin.install "create_iam_accounts.py"
    mv "#{bin}/create_iam_accounts.py", "#{bin}/smartiamcreator"
  end

  def test
    system "#{bin}/create_iam_accounts"
  end
end