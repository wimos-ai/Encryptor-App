# -*- mode: python ; coding: utf-8 -*-


block_cipher = None


a = Analysis(['__main__.pyw'],
             pathex=[],
             binaries=[],
             datas=[],
             hiddenimports=['FernetEncryption.py'],
             hookspath=[],
             hooksconfig={},
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,  
          [],
          name='Encryptor',
          debug=False,
          bootloader_ignore_signals=False,
          strip=True,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=False,
          disable_windowed_traceback=True,
          target_arch=None,
          codesign_identity=None,
          entitlements_file=None , icon='C:\\Users\\willm\\Documents\\Programming\\Python\\finishedUtilities\\Sigma.ico')
