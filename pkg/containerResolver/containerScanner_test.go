//go:build !coverage

package containersResolver_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	containersResolver "github.com/Checkmarx/containers-resolver/pkg/containerResolver"
	"github.com/Checkmarx/containers-syft-packages-extractor/pkg/syftPackagesExtractor"
	"github.com/Checkmarx/containers-types/types"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock for ImagesExtractorInterface
type MockImagesExtractor struct {
	mock.Mock
}

func (m *MockImagesExtractor) ExtractFiles(scanPath string) (types.FileImages, map[string]map[string]string, string, error) {
	args := m.Called(scanPath)
	return args.Get(0).(types.FileImages), args.Get(1).(map[string]map[string]string), args.String(2), args.Error(3)
}

func (m *MockImagesExtractor) ExtractAndMergeImagesFromFiles(files types.FileImages, images []types.ImageModel, settingsFiles map[string]map[string]string) ([]types.ImageModel, error) {
	args := m.Called(files, images, settingsFiles)
	return args.Get(0).([]types.ImageModel), args.Error(1)
}

func (m *MockImagesExtractor) SaveObjectToFile(folderPath string, obj interface{}) error {
	return m.Called(folderPath, obj).Error(0)
}

// Mock for SyftPackagesExtractorInterface
type MockSyftPackagesExtractor struct {
	mock.Mock
}

func (m *MockSyftPackagesExtractor) AnalyzeImages(images []types.ImageModel) ([]*syftPackagesExtractor.ContainerResolution, error) {
	args := m.Called(images)
	return args.Get(0).([]*syftPackagesExtractor.ContainerResolution), args.Error(1)
}

func (m *MockSyftPackagesExtractor) AnalyzeImagesWithPlatform(images []types.ImageModel, platform string) ([]*syftPackagesExtractor.ContainerResolution, error) {
	args := m.Called(images, platform)
	return args.Get(0).([]*syftPackagesExtractor.ContainerResolution), args.Error(1)
}

func createTestFolder(dir string) {
	// Create the directory if it doesn't exist
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			log.Err(err)
		}
	}
}

func TestResolve(t *testing.T) {
	mockImagesExtractor := new(MockImagesExtractor)
	mockSyftPackagesExtractor := new(MockSyftPackagesExtractor)

	createTestFolder("../../test_files/resolution")

	resolver := containersResolver.ContainersResolver{
		ImagesExtractor:       mockImagesExtractor,
		SyftPackagesExtractor: mockSyftPackagesExtractor,
	}

	sampleFileImages := types.FileImages{
		Dockerfile: []types.FilePath{
			{FullPath: "absolute/path/to/Dockerfile1", RelativePath: "relative/path/to/Dockerfile1"},
			{FullPath: "absolute/path/to/Dockerfile2", RelativePath: "relative/path/to/Dockerfile2"},
		},
		DockerCompose: []types.FilePath{
			{FullPath: "absolute/path/to/docker-compose.yml", RelativePath: "relative/path/to/docker-compose.yml"},
		},
		Helm: []types.HelmChartInfo{
			{
				Directory:  "absolute/path/to/helm/chart",
				ValuesFile: "relative/path/to/values.yaml",
				TemplateFiles: []types.FilePath{
					{FullPath: "absolute/path/to/template1", RelativePath: "relative/path/to/template1"},
				},
			},
		},
	}

	scanPath := "../../test_files"

	resolutionFolderPath := "../../test_files/resolution"

	images := []string{"image1", "image2"}

	expectedResolution := []*syftPackagesExtractor.ContainerResolution{
		{
			ContainerImage: syftPackagesExtractor.ContainerImage{
				ImageName:      "image1:blabla",
				ImageTag:       "latest",
				Distribution:   "debian",
				ImageHash:      "sha256:123abc",
				ImageId:        "id12345",
				ImageLocations: []syftPackagesExtractor.ImageLocation{{Origin: "Dockerfile", Path: "/path/to/Dockerfile"}},
				History: []syftPackagesExtractor.Layer{
					{Order: 1, Size: 12345, LayerId: "layer1", Command: "ADD /file1 /"},
				},
			},
			ContainerPackages: []syftPackagesExtractor.ContainerPackage{
				{
					Name:          "package1",
					Version:       "1.0.0",
					Distribution:  "debian",
					Type:          "binary",
					SourceName:    "src-package1",
					SourceVersion: "1.0.0",
					Licenses:      []string{"MIT"},
					LayerIds:      []string{"layer1"},
				},
			},
		},
	}

	t.Run("Success scenario", func(t *testing.T) {
		checkmarxPath := filepath.Join(resolutionFolderPath, ".checkmarx", "containers")
		createTestFolder(checkmarxPath)

		mockImagesExtractor.On("ExtractFiles", scanPath).
			Return(sampleFileImages, map[string]map[string]string{"settings.json": {"key": "value"}}, "/output/path", nil)
		mockImagesExtractor.On("ExtractAndMergeImagesFromFiles",
			sampleFileImages,
			types.ToImageModels(images),
			map[string]map[string]string{"settings.json": {"key": "value"}}).
			Return([]types.ImageModel{{Name: "image1"}}, nil)
		mockSyftPackagesExtractor.On("AnalyzeImagesWithPlatform", mock.Anything, mock.Anything).Return(expectedResolution, nil)
		mockImagesExtractor.On("SaveObjectToFile", checkmarxPath, expectedResolution).Return(nil)

		err := resolver.Resolve(scanPath, resolutionFolderPath, images, true)
		assert.NoError(t, err)

		mockImagesExtractor.AssertCalled(t, "ExtractFiles", scanPath)
		mockImagesExtractor.AssertCalled(t, "ExtractAndMergeImagesFromFiles", sampleFileImages, mock.Anything, mock.Anything)
		mockSyftPackagesExtractor.AssertCalled(t, "AnalyzeImagesWithPlatform", mock.Anything, "linux/amd64")
		mockImagesExtractor.AssertCalled(t, "SaveObjectToFile", checkmarxPath, expectedResolution)
	})

	t.Run("ScanPath Validation failure", func(t *testing.T) {
		mockImagesExtractor.ExpectedCalls = nil
		mockImagesExtractor.Calls = nil
		// Test
		err := resolver.Resolve(scanPath, "", images, false)
		assert.Error(t, err)
		assert.Equal(t, "stat : no such file or directory", err.Error())
	})

	t.Run("ExtractFilesError", func(t *testing.T) {
		mockImagesExtractor.ExpectedCalls = nil
		mockImagesExtractor.Calls = nil

		checkmarxPath := filepath.Join(resolutionFolderPath, ".checkmarx", "containers")
		createTestFolder(checkmarxPath)

		mockImagesExtractor.On("ExtractFiles", scanPath).
			Return(sampleFileImages, map[string]map[string]string{"settings.json": {"key": "value"}}, "/output/path",
				errors.New("invalid path"))

		err := resolver.Resolve(scanPath, resolutionFolderPath, images, false)
		assert.Error(t, err)
		assert.Equal(t, "invalid path", err.Error())
		mockImagesExtractor.AssertCalled(t, "ExtractFiles", scanPath)
	})

	t.Run("Error in AnalyzeImages", func(t *testing.T) {
		mockImagesExtractor.ExpectedCalls = nil
		mockImagesExtractor.Calls = nil
		mockSyftPackagesExtractor.ExpectedCalls = nil
		mockSyftPackagesExtractor.Calls = nil

		checkmarxPath := filepath.Join(resolutionFolderPath, ".checkmarx", "containers")
		createTestFolder(checkmarxPath)

		mockImagesExtractor.On("ExtractFiles", scanPath).
			Return(sampleFileImages, map[string]map[string]string{"settings.json": {"key": "value"}}, "/output/path", nil)

		mockImagesExtractor.On("ExtractAndMergeImagesFromFiles", sampleFileImages, types.ToImageModels(images),
			map[string]map[string]string{"settings.json": {"key": "value"}}).
			Return([]types.ImageModel{{Name: "image1"}}, nil)

		mockSyftPackagesExtractor.On("AnalyzeImagesWithPlatform", mock.Anything, "linux/amd64").Return(expectedResolution, errors.New("error analyzing images"))

		err := resolver.Resolve(scanPath, resolutionFolderPath, images, false)
		assert.Error(t, err)
	})
}
