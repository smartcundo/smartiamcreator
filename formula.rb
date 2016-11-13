require 'formula'

class IAMCredentialsCreator < Formula
  homepage 'https://github.com/smartcundo/smartiamcreator'
  url 'https://github.com/smartcundo/smartiamcreator/archive/0.0.1.tar.gz'
  sha256 '232fa18d7a92d95bc32161de3c2e9c9fc131cb8b6a28d55ccaff3029d24170f0'

  def install
    bin.install "formula-smartiamcreator/create_iam_accounts.py"
    mv "#{bin}/formula-smartiamcreator/create_iam_accounts.py", "#{bin}/smartiamcreator"
  end

  def test
    system "#{bin}/create_iam_accounts"
  end
end