require 'blobfish/signer'

$trusted_cas = ['trusted_anchors/Blobfish Root CA (demo).pem', 'trusted_anchors/Llama.pe Root CA.pem']

def validate_and_display_results(signed_file)
  puts "Validating #{signed_file}..."
  validation_results = Blobfish::Signer::PdfSigner.verify signed_file, trusted_anchors: $trusted_cas
  validation_results.each do |result|
    puts "  - Signature #{result[:sig_name]}:"
    if result.include? :error
      puts "    - Failed: #{result[:error]}"
    else
      signer_cert = result[:chain][0]
      puts "    - Signer certificate serial number: #{signer_cert.serial}"
      puts "    - Signer certificate subject DN: #{signer_cert.subject}"
      puts "    - Signer certificate issuer DN: #{signer_cert.issuer}"
    end
  end
end

validate_and_display_results('sample_pdfs/sample_signed_valid.pdf')
validate_and_display_results('sample_pdfs/sample_signed_twice.pdf')
validate_and_display_results('sample_pdfs/sample_signed_untrusted.pdf')
validate_and_display_results('sample_pdfs/sample_signed_corrupted.pdf')
validate_and_display_results('sample_pdfs/sample_signed_twice_one_corrupted.pdf')
