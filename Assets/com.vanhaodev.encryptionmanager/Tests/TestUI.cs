#if UNITY_EDITOR
using UnityEditor;
using UnityEngine;

namespace vanhaodev.encryptionmanager.tests
{
	public class TestUI : EditorWindow
	{
		private int _selectedTab;
		private readonly string[] _tabs = { "Encryption", "Hash" };
		private Vector2 _scrollPosition;
		private GUIStyle _labelStyle;
		private GUIStyle _buttonStyle;
		private GUIStyle _textAreaStyle;

		// Encryption state
		private EncryptType _encryptType = EncryptType.Xor;
		private string _encryptInput = "Hello World!";
		private string _encryptOutput = "";
		private byte _xorKey;
		private string _aesKey = "";
		private bool _aesUseString = true;

		// Hash state
		private string _hashInput = "MyPassword123";
		private string _hashOutput = "";
		private string _verifyInput = "";
		private string _verifyResult = "";
		private bool _initialized;

		[MenuItem("Tools/Encryption Manager/Test UI")]
		public static void ShowWindow()
		{
			var window = GetWindow<TestUI>("Encryption Test");
			window.minSize = new Vector2(400, 600);
			window.Show();
		}

		void Init()
		{
			if (_initialized) return;
			_initialized = true;

			_xorKey = EncryptionManager.GetXorAutoKey();
			var key = EncryptionManager.GetAesAutoKey();
			_aesKey = System.Convert.ToBase64String(key);
			HashManager.RegisterPbkdf2();
		}

		void OnGUI()
		{
			Init();
			InitStyles();

			_selectedTab = GUILayout.Toolbar(_selectedTab, _tabs, GUILayout.Height(30));
			GUILayout.Space(10);

			_scrollPosition = GUILayout.BeginScrollView(_scrollPosition);

			if (_selectedTab == 0)
				DrawEncryptionTab();
			else
				DrawHashTab();

			GUILayout.EndScrollView();
		}

		void InitStyles()
		{
			if (_labelStyle != null) return;

			_labelStyle = new GUIStyle(EditorStyles.boldLabel) { fontSize = 14 };
			_buttonStyle = new GUIStyle(GUI.skin.button) { fontSize = 12 };
			_textAreaStyle = new GUIStyle(EditorStyles.textArea) { fontSize = 12, wordWrap = true };
		}

		void DrawEncryptionTab()
		{
			EditorGUILayout.LabelField("Encryption Test", EditorStyles.boldLabel);
			GUILayout.Space(10);

			// Type selection
			EditorGUILayout.LabelField($"Type: {_encryptType}");
			GUILayout.BeginHorizontal();
			if (GUILayout.Button("XOR", GUILayout.Height(30)))
				_encryptType = EncryptType.Xor;
			if (GUILayout.Button("AES", GUILayout.Height(30)))
				_encryptType = EncryptType.Aes;
			GUILayout.EndHorizontal();

			GUILayout.Space(10);

			// Key display based on type
			if (_encryptType == EncryptType.Xor)
			{
				GUILayout.BeginHorizontal();
				EditorGUILayout.LabelField($"XOR Key: {_xorKey} (0x{_xorKey:X2})");
				if (GUILayout.Button("Regenerate", GUILayout.Width(100)))
				{
					_xorKey = EncryptionManager.GetXorAutoKey();
				}
				GUILayout.EndHorizontal();
			}
			else
			{
				GUILayout.BeginHorizontal();
				EditorGUILayout.LabelField("Key Mode:", GUILayout.Width(70));
				if (GUILayout.Button(_aesUseString ? "String" : "Base64", GUILayout.Width(80)))
				{
					_aesUseString = !_aesUseString;
					_aesKey = "";
				}
				if (GUILayout.Button("Auto Generate", GUILayout.Width(100)))
				{
					var key = EncryptionManager.GetAesAutoKey();
					_aesKey = System.Convert.ToBase64String(key);
					_aesUseString = false;
					_encryptOutput = "New key generated!";
				}
				GUILayout.EndHorizontal();

				EditorGUILayout.LabelField(_aesUseString ? "AES Key (any text):" : "AES Key (Base64):");
				_aesKey = EditorGUILayout.TextField(_aesKey);
				EditorGUILayout.HelpBox("IV is auto-generated per encryption and embedded in output.", MessageType.Info);

				if (GUILayout.Button("Apply Key", GUILayout.Height(25)))
				{
					try
					{
						if (_aesUseString)
						{
							EncryptionManager.RegisterAes(_aesKey);
						}
						else
						{
							var key = System.Convert.FromBase64String(_aesKey);
							EncryptionManager.RegisterAes(key);
						}
						_encryptOutput = "Key applied!";
					}
					catch (System.Exception e)
					{
						_encryptOutput = $"Error: {e.Message}";
					}
				}
			}

			GUILayout.Space(10);
			EditorGUILayout.LabelField("Input:");
			_encryptInput = EditorGUILayout.TextArea(_encryptInput, GUILayout.Height(60));

			GUILayout.Space(10);
			GUILayout.BeginHorizontal();
			if (GUILayout.Button("Encrypt", GUILayout.Height(30)))
			{
				try
				{
					_encryptOutput = EncryptionManager.Encrypt(_encryptType, _encryptInput);
				}
				catch (System.Exception e)
				{
					_encryptOutput = $"Error: {e.Message}";
				}
			}
			if (GUILayout.Button("Decrypt", GUILayout.Height(30)))
			{
				try
				{
					_encryptOutput = EncryptionManager.Decrypt(_encryptType, _encryptInput);
				}
				catch (System.Exception e)
				{
					_encryptOutput = $"Error: {e.Message}";
				}
			}
			GUILayout.EndHorizontal();

			GUILayout.Space(10);
			EditorGUILayout.LabelField("Output:");
			_encryptOutput = EditorGUILayout.TextArea(_encryptOutput, GUILayout.Height(60));

			GUILayout.Space(10);
			if (GUILayout.Button("Copy Output to Input", GUILayout.Height(25)))
			{
				_encryptInput = _encryptOutput;
			}
		}

		void DrawHashTab()
		{
			EditorGUILayout.LabelField("Hash Test (PBKDF2)", EditorStyles.boldLabel);
			GUILayout.Space(10);

			EditorGUILayout.LabelField("Input:");
			_hashInput = EditorGUILayout.TextArea(_hashInput, GUILayout.Height(60));

			GUILayout.Space(10);
			if (GUILayout.Button("Hash", GUILayout.Height(30)))
			{
				_hashOutput = HashManager.Hash(HashType.Pbkdf2, _hashInput);
				_verifyInput = _hashInput; // Auto copy for easy testing
				_verifyResult = "";
			}

			GUILayout.Space(10);
			EditorGUILayout.LabelField("Hash Output (salt+hash combined):");
			_hashOutput = EditorGUILayout.TextArea(_hashOutput, GUILayout.Height(80));

			GUILayout.Space(10);
			EditorGUILayout.LabelField("Verify Input (type password to verify):");
			_verifyInput = EditorGUILayout.TextArea(_verifyInput, GUILayout.Height(50));

			GUILayout.Space(10);
			GUILayout.BeginHorizontal();
			if (GUILayout.Button("Verify", GUILayout.Height(30)))
			{
				if (string.IsNullOrEmpty(_hashOutput))
				{
					_verifyResult = "Hash first!";
				}
				else
				{
					try
					{
						bool isValid = HashManager.Verify(HashType.Pbkdf2, _verifyInput, _hashOutput);
						_verifyResult = isValid ? "VALID" : "INVALID";
					}
					catch (System.Exception e)
					{
						_verifyResult = $"Error: {e.Message}";
					}
				}
			}
			if (GUILayout.Button("Copy Input", GUILayout.Height(30)))
			{
				_verifyInput = _hashInput;
			}
			GUILayout.EndHorizontal();

			GUILayout.Space(5);
			EditorGUILayout.LabelField($"Result: {_verifyResult}", EditorStyles.boldLabel);
		}
	}
}
#endif
