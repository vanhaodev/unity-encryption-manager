namespace vanhaodev.encryptionmanager
{
	public interface IHash
	{
		/// <summary>Compute hash with auto-generated salt. Returns combined salt+hash bytes.</summary>
		byte[] Compute(byte[] data);

		/// <summary>Verify data against combined salt+hash bytes.</summary>
		bool Verify(byte[] data, byte[] combined);
	}
}